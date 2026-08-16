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
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


PORT = int(os.environ.get("PORT", "8080"))
DEFAULT_PUBLIC_HOST = "https://phone.dallasclounch.com"
RELAY_TIMEOUT_SECONDS = 8
SMS_PATHS = {"/twilio/sms", "/sms"}
STATUS_PATH = "/twilio/status"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _public_host() -> str:
    return _env("PUBLIC_HOST", DEFAULT_PUBLIC_HOST).rstrip("/")


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


class Handler(BaseHTTPRequestHandler):
    server_version = "DaraPhoneBridge/2.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        _json_log("http_access", client=self.address_string(), message=fmt % args)

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


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(json.dumps({"event": "server_started", "port": PORT}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
