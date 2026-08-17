#!/usr/bin/env python3
"""Twilio SMS edge bridge for Dara Public PA.

Voice routing intentionally remains on Vapi; this service only handles SMS and
SMS status callbacks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


PORT = int(os.environ.get("PORT", "8080"))
DEFAULT_PUBLIC_HOST = "https://phone.dallasclounch.com"
RELAY_TIMEOUT_SECONDS = 8
DEFAULT_VAPI_RELAY_TIMEOUT_SECONDS = 58
MAX_VAPI_BODY_BYTES = 2 * 1024 * 1024
VAPI_RELAY_ATTEMPTS = 3
VAPI_RELAY_BACKOFF_SECONDS = 0.2
SMS_PATHS = {"/twilio/sms", "/sms"}
STATUS_PATH = "/twilio/status"
VAPI_EVENTS_PATH = "/vapi/events"
VAPI_TOOLS_PATH = "/vapi/tools"
VAPI_ACTIONS_PATH = "/vapi/actions"
VAPI_SYNC_PATHS = {VAPI_TOOLS_PATH, VAPI_ACTIONS_PATH}
VAPI_PATHS = {VAPI_EVENTS_PATH, VAPI_TOOLS_PATH, VAPI_ACTIONS_PATH}


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _public_host() -> str:
    return _env("PUBLIC_HOST", DEFAULT_PUBLIC_HOST).rstrip("/")


def _vapi_webhook_secret() -> str:
    return _env("VAPI_WEBHOOK_SECRET") or _env("TWILIO_AUTH_TOKEN")


def _vapi_relay_timeout_seconds() -> float:
    raw_timeout = _env("VAPI_RELAY_TIMEOUT_SECONDS", str(DEFAULT_VAPI_RELAY_TIMEOUT_SECONDS))
    try:
        timeout = float(raw_timeout)
    except ValueError:
        return DEFAULT_VAPI_RELAY_TIMEOUT_SECONDS
    if timeout <= 0:
        return DEFAULT_VAPI_RELAY_TIMEOUT_SECONDS
    return timeout


def _replace_path_suffix(url: str, suffixes: tuple[str, ...], target_path: str) -> str:
    parsed = urllib.parse.urlparse(url)
    for suffix in suffixes:
        if parsed.path.endswith(suffix):
            path = f"{parsed.path[:-len(suffix)]}{target_path}"
            return urllib.parse.urlunparse(parsed._replace(path=path))
    return ""


def _vapi_relay_url(path: str = VAPI_EVENTS_PATH) -> str:
    dedicated_url = _env("VAPI_RELAY_URL")
    if dedicated_url:
        matched = _replace_path_suffix(dedicated_url, tuple(sorted(VAPI_PATHS)), path)
        if matched:
            return matched
        parsed = urllib.parse.urlparse(dedicated_url)
        base_path = parsed.path.rstrip("/")
        return urllib.parse.urlunparse(parsed._replace(path=f"{base_path}{path}"))

    relay_url = _env("RELAY_URL")
    if not relay_url:
        return ""

    return _replace_path_suffix(relay_url, ("/twilio/sms", "/sms"), path)


def _mask_phone(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) < 4:
        return "****"
    return f"***{digits[-4:]}"


def _parse_form(raw: bytes) -> dict[str, str]:
    parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def _twilio_signature(url: str, params: dict[str, str], auth_token: str) -> str:
    signed = url + "".join(f"{key}{params[key]}" for key in sorted(params))
    digest = hmac.new(auth_token.encode("utf-8"), signed.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")


def _validate_twilio(path: str, params: dict[str, str], signature: str) -> bool:
    auth_token = _env("TWILIO_AUTH_TOKEN")
    if not auth_token or not signature:
        return False
    expected = _twilio_signature(f"{_public_host()}{path}", params, auth_token)
    return hmac.compare_digest(expected, signature)


def _extract_bearer(value: str) -> str:
    scheme, _, token = value.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return ""
    return token.strip()


def _validate_vapi(headers: Any) -> bool:
    secret = _vapi_webhook_secret()
    if not secret:
        return False

    candidates = [
        headers.get("x-vapi-secret", ""),
        _extract_bearer(headers.get("Authorization", "")),
    ]
    for candidate in candidates:
        if hmac.compare_digest(candidate.encode("utf-8"), secret.encode("utf-8")):
            return True
    return False


def _json_log(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    print(json.dumps(payload, sort_keys=True), file=sys.stderr, flush=True)


def _safe_sid(params: dict[str, str]) -> str:
    return params.get("MessageSid") or params.get("SmsSid") or ""


def _relay_form(url: str, raw_body: bytes, signature: str, content_type: str) -> tuple[int, bytes, str]:
    req = urllib.request.Request(
        url,
        data=raw_body,
        method="POST",
        headers={
            "Content-Type": content_type or "application/x-www-form-urlencoded",
            "X-Twilio-Signature": signature,
            "User-Agent": "dara-phone-bridge/2.0",
        },
    )
    with urllib.request.urlopen(req, timeout=RELAY_TIMEOUT_SECONDS) as response:
        response_body = response.read()
        return response.status, response_body, response.headers.get("Content-Type", "text/xml")


def _relay_form_status(url: str, raw_body: bytes, signature: str, content_type: str) -> int:
    status, _, _ = _relay_form(url, raw_body, signature, content_type)
    return status


def _relay_json_once(url: str, raw_body: bytes, secret: str, timeout: float) -> tuple[int, bytes, str]:
    req = urllib.request.Request(
        url,
        data=raw_body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-vapi-secret": secret,
            "User-Agent": "dara-phone-bridge/2.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        response_body = response.read()
        return response.status, response_body, response.headers.get("Content-Type", "application/json")


def _is_relay_timeout_error(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return True
    return False


def _is_transient_relay_error(exc: BaseException) -> bool:
    if _is_relay_timeout_error(exc):
        return False
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in {408, 429, 500, 502, 503, 504}
    return isinstance(exc, (TimeoutError, urllib.error.URLError))


def _relay_json(
    url: str,
    raw_body: bytes,
    secret: str,
    log_fields: dict[str, Any],
    timeout: float = RELAY_TIMEOUT_SECONDS,
) -> tuple[int, bytes, str]:
    attempts = VAPI_RELAY_ATTEMPTS
    for attempt in range(1, attempts + 1):
        try:
            return _relay_json_once(url, raw_body, secret, timeout)
        except urllib.error.HTTPError as exc:
            if not _is_transient_relay_error(exc) or attempt == attempts:
                body = exc.read()
                content_type = exc.headers.get("Content-Type", "application/json") if exc.headers else "application/json"
                return exc.code, body, content_type
            _json_log("vapi_relay_retry", attempt=attempt, status=exc.code, error="http_error", **log_fields)
        except Exception as exc:  # noqa: BLE001
            if not _is_transient_relay_error(exc) or attempt == attempts:
                raise
            _json_log("vapi_relay_retry", attempt=attempt, error=type(exc).__name__, **log_fields)
        time.sleep(VAPI_RELAY_BACKOFF_SECONDS * (2 ** (attempt - 1)))
    raise RuntimeError("unreachable_vapi_relay_state")


def _extract_call_id(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    call = payload.get("call")
    if isinstance(call, dict):
        for key in ("id", "callId"):
            value = call.get(key)
            if isinstance(value, str):
                return value
    for key in ("callId", "call_id"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    message = payload.get("message")
    if isinstance(message, dict):
        return _extract_call_id(message)
    return ""


def _extract_tool_call_ids(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    candidates: list[Any] = []
    for key in ("toolCall", "tool_call"):
        value = payload.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    for key in ("toolCalls", "tool_calls", "toolCallList"):
        value = payload.get(key)
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))

    ids: list[str] = []
    for item in candidates:
        for key in ("id", "toolCallId", "tool_call_id"):
            value = item.get(key)
            if isinstance(value, str) and value not in ids:
                ids.append(value)
                break
    message = payload.get("message")
    if isinstance(message, dict):
        for value in _extract_tool_call_ids(message):
            if value not in ids:
                ids.append(value)
    return ids[:20]


def _is_tool_calls_envelope(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("type") == "tool-calls":
        return True
    message = payload.get("message")
    if isinstance(message, dict) and message.get("type") == "tool-calls":
        return True
    return bool(_extract_tool_call_ids(payload))


class Handler(BaseHTTPRequestHandler):
    server_version = "DaraPhoneBridge/2.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        _json_log(
            "http_access",
            client=self.address_string(),
            method=getattr(self, "command", ""),
            path=urllib.parse.urlparse(getattr(self, "path", "")).path,
        )

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_read()

    def do_GET(self) -> None:  # noqa: N802
        self._handle_read()

    def _handle_read(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/health":
            payload = {
                "ok": True,
                "service": "dara-phone-bridge",
                "sms": True,
                "voice_on_vapi": True,
                "twilio_auth_configured": bool(_env("TWILIO_AUTH_TOKEN")),
                "twilio_account_configured": bool(_env("TWILIO_ACCOUNT_SID")),
                "relay_configured": bool(_env("RELAY_URL")),
                "relay_status_configured": bool(_env("RELAY_STATUS_URL")),
                "vapi_webhook_secret_configured": bool(_vapi_webhook_secret()),
                "vapi_relay_configured": bool(_vapi_relay_url(VAPI_EVENTS_PATH)),
                "vapi_events_relay_configured": bool(_vapi_relay_url(VAPI_EVENTS_PATH)),
                "vapi_tools_relay_configured": bool(_vapi_relay_url(VAPI_TOOLS_PATH)),
                "vapi_actions_relay_configured": bool(_vapi_relay_url(VAPI_ACTIONS_PATH)),
            }
            self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
            return

        if path in {"/", ""}:
            html = (
                "<!doctype html><meta charset='utf-8'>"
                "<title>Dara phone bridge</title>"
                "<body style='font-family:sans-serif;max-width:42rem;margin:4rem auto;color:#222'>"
                "<h1>Dara phone bridge</h1>"
                "<p>SMS is handled by this Twilio edge bridge at <code>/twilio/sms</code>. "
                "Voice remains on Vapi.</p>"
                "</body>"
            )
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return

        self._send(404, b'{"error":"not_found"}')

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path in SMS_PATHS:
            self._handle_sms(path)
            return
        if path == STATUS_PATH:
            self._handle_status(path)
            return
        if path in VAPI_PATHS:
            self._handle_vapi(path)
            return
        self._send(404, b'{"error":"not_found"}')

    def _read_form_request(self) -> tuple[bytes, dict[str, str], str, str]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw_body = self.rfile.read(length) if length else b""
        params = _parse_form(raw_body)
        signature = self.headers.get("X-Twilio-Signature", "")
        content_type = self.headers.get("Content-Type", "application/x-www-form-urlencoded")
        return raw_body, params, signature, content_type

    def _handle_sms(self, path: str) -> None:
        raw_body, params, signature, content_type = self._read_form_request()
        message_sid = _safe_sid(params)
        if not _validate_twilio(path, params, signature):
            _json_log("invalid_signature", endpoint="sms", path=path, message_sid=message_sid)
            self._send(403, b'{"error":"invalid_signature"}')
            return

        _json_log(
            "sms_accepted",
            path=path,
            account_sid_configured=bool(_env("TWILIO_ACCOUNT_SID")),
            message_sid=message_sid,
            **{"from": _mask_phone(params.get("From", "")), "to": _mask_phone(params.get("To", ""))},
        )

        relay_url = _env("RELAY_URL")
        if not relay_url:
            _json_log("relay_failed", endpoint="sms", message_sid=message_sid, error="relay_url_unset")
            self._send(502, b'{"error":"relay_failed"}')
            return

        try:
            status, body, response_content_type = _relay_form(relay_url, raw_body, signature, content_type)
        except urllib.error.HTTPError as exc:
            _json_log("relay_failed", endpoint="sms", message_sid=message_sid, status=exc.code, error="http_error")
            self._send(502, b'{"error":"relay_failed"}')
            return
        except Exception as exc:  # noqa: BLE001
            _json_log("relay_failed", endpoint="sms", message_sid=message_sid, error=type(exc).__name__)
            self._send(502, b'{"error":"relay_failed"}')
            return

        _json_log("sms_relayed", message_sid=message_sid, status=status)
        if status >= 400:
            _json_log("relay_failed", endpoint="sms", message_sid=message_sid, status=status, error="bad_status")
            self._send(502, b'{"error":"relay_failed"}')
            return
        self._send(status, body, response_content_type)

    def _handle_status(self, path: str) -> None:
        raw_body, params, signature, content_type = self._read_form_request()
        message_sid = _safe_sid(params)
        if not _validate_twilio(path, params, signature):
            _json_log("invalid_signature", endpoint="status", path=path, message_sid=message_sid)
            self._send(403, b'{"error":"invalid_signature"}')
            return

        _json_log(
            "status_callback",
            message_sid=message_sid,
            status=params.get("MessageStatus") or params.get("SmsStatus") or "",
            error_code=params.get("ErrorCode", ""),
            **{"from": _mask_phone(params.get("From", "")), "to": _mask_phone(params.get("To", ""))},
        )

        relay_url = _env("RELAY_STATUS_URL")
        if relay_url:
            try:
                status = _relay_form_status(relay_url, raw_body, signature, content_type)
            except urllib.error.HTTPError as exc:
                _json_log("relay_failed", endpoint="status", message_sid=message_sid, status=exc.code, error="http_error")
                self._send(502, b'{"error":"relay_failed"}')
                return
            except Exception as exc:  # noqa: BLE001
                _json_log("relay_failed", endpoint="status", message_sid=message_sid, error=type(exc).__name__)
                self._send(502, b'{"error":"relay_failed"}')
                return
            if status >= 400:
                _json_log("relay_failed", endpoint="status", message_sid=message_sid, status=status, error="bad_status")
                self._send(502, b'{"error":"relay_failed"}')
                return
            _json_log("status_relayed", message_sid=message_sid, status=status)

        self._send(204)

    def _read_json_request(self, max_bytes: int) -> tuple[bytes | None, Any | None, str | None]:
        length_header = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(length_header)
        except ValueError:
            return None, None, "invalid_content_length"

        if length < 0:
            return None, None, "invalid_content_length"
        if length > max_bytes:
            return None, None, "body_too_large"

        raw_body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, None, "invalid_json"
        return raw_body, payload, None

    def _handle_vapi(self, path: str) -> None:
        webhook_secret = _vapi_webhook_secret()
        relay_url = _vapi_relay_url(path)
        if not webhook_secret or not relay_url:
            _json_log(
                "vapi_config_missing",
                endpoint=path,
                webhook_secret_configured=bool(webhook_secret),
                relay_configured=bool(relay_url),
            )
            self._send(503, b'{"error":"vapi_not_configured"}')
            return

        if not _validate_vapi(self.headers):
            _json_log("vapi_auth_failed", endpoint=path)
            self._send(403, b'{"error":"forbidden"}')
            return

        raw_body, payload, error = self._read_json_request(MAX_VAPI_BODY_BYTES)
        if error == "body_too_large":
            _json_log("vapi_validation_failed", endpoint=path, reason=error)
            self._send(413, b'{"error":"body_too_large"}')
            return
        if error:
            _json_log("vapi_validation_failed", endpoint=path, reason=error)
            self._send(400, b'{"error":"invalid_json"}')
            return

        call_id = _extract_call_id(payload)
        tool_call_ids = _extract_tool_call_ids(payload)
        log_fields = {"endpoint": path, "call_id": call_id, "tool_call_ids": tool_call_ids}
        sync_endpoint = path in VAPI_SYNC_PATHS
        tool_calls_event = path == VAPI_EVENTS_PATH and _is_tool_calls_envelope(payload)
        sync_response = sync_endpoint or tool_calls_event
        relay_timeout = _vapi_relay_timeout_seconds() if sync_response else RELAY_TIMEOUT_SECONDS
        _json_log("vapi_relay_started", **log_fields)

        try:
            status, body, response_content_type = _relay_json(
                relay_url,
                raw_body or b"",
                webhook_secret,
                log_fields,
                timeout=relay_timeout,
            )
        except Exception as exc:  # noqa: BLE001
            _json_log("vapi_relay_failed", error=type(exc).__name__, **log_fields)
            self._send(502, b'{"error":"relay_failed"}')
            return

        if status >= 400:
            if sync_response:
                _json_log("vapi_relayed", status=status, **log_fields)
                self._send(status, body, response_content_type)
                return
            _json_log("vapi_relay_failed", status=status, error="bad_status", **log_fields)
            self._send(502, b'{"error":"relay_failed"}')
            return

        _json_log("vapi_relayed", status=status, **log_fields)
        if sync_endpoint or (tool_calls_event and body):
            self._send(status, body, response_content_type)
            return
        self._send(204)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(json.dumps({"event": "server_started", "port": PORT}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
