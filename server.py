#!/usr/bin/env python3
"""Twilio SMS and authenticated Vapi event edge bridge for Dara Public PA."""

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
MAX_VAPI_BODY_BYTES = 2 * 1024 * 1024
SMS_PATHS = {"/twilio/sms", "/sms"}
STATUS_PATH = "/twilio/status"
VAPI_EVENTS_PATH = "/vapi/events"

def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()

def _public_host() -> str:
    return _env("PUBLIC_HOST", DEFAULT_PUBLIC_HOST).rstrip("/")

def _vapi_webhook_secret() -> str:
    return _env("VAPI_WEBHOOK_SECRET") or _env("TWILIO_AUTH_TOKEN")

def _vapi_relay_url() -> str:
    dedicated_url = _env("VAPI_RELAY_URL")
    if dedicated_url:
        return dedicated_url
    relay_url = _env("RELAY_URL")
    if not relay_url:
        return ""
    parsed = urllib.parse.urlparse(relay_url)
    for suffix in ("/twilio/sms", "/sms"):
        if parsed.path.endswith(suffix):
            path = f"{parsed.path[:-len(suffix)]}{VAPI_EVENTS_PATH}"
            return urllib.parse.urlunparse(parsed._replace(path=path))
    return ""

def _mask_phone(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    return "****" if len(digits) < 4 else f"***{digits[-4:]}"

def _parse_form(raw: bytes) -> dict[str, str]:
    parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}

def _twilio_signature(url: str, params: dict[str, str], auth_token: str) -> str:
    signed = url + "".join(f"{key}{params[key]}" for key in sorted(params))
    digest = hmac.new(auth_token.encode(), signed.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")

def _validate_twilio(path: str, params: dict[str, str], signature: str) -> bool:
    token = _env("TWILIO_AUTH_TOKEN")
    if not token or not signature:
        return False
    return hmac.compare_digest(_twilio_signature(f"{_public_host()}{path}", params, token), signature)

def _extract_bearer(value: str) -> str:
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token else ""

def _validate_vapi(headers: Any) -> bool:
    secret = _vapi_webhook_secret()
    if not secret:
        return False
    for candidate in (headers.get("x-vapi-secret", ""), _extract_bearer(headers.get("Authorization", ""))):
        if hmac.compare_digest(candidate.encode(), secret.encode()):
            return True
    return False

def _json_log(event: str, **fields: Any) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), file=sys.stderr, flush=True)

def _safe_sid(params: dict[str, str]) -> str:
    return params.get("MessageSid") or params.get("SmsSid") or ""

def _relay_form(url: str, raw_body: bytes, signature: str, content_type: str) -> tuple[int, bytes, str]:
    req = urllib.request.Request(url, data=raw_body, method="POST", headers={"Content-Type": content_type or "application/x-www-form-urlencoded", "X-Twilio-Signature": signature, "User-Agent": "dara-phone-bridge/2.0"})
    with urllib.request.urlopen(req, timeout=RELAY_TIMEOUT_SECONDS) as response:
        return response.status, response.read(), response.headers.get("Content-Type", "text/xml")

def _relay_json(url: str, raw_body: bytes, secret: str) -> int:
    req = urllib.request.Request(url, data=raw_body, method="POST", headers={"Content-Type": "application/json", "x-vapi-secret": secret, "User-Agent": "dara-phone-bridge/2.0"})
    with urllib.request.urlopen(req, timeout=RELAY_TIMEOUT_SECONDS) as response:
        response.read()
        return response.status

class Handler(BaseHTTPRequestHandler):
    server_version = "DaraPhoneBridge/2.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        _json_log("http_access", client=self.address_string(), method=getattr(self, "command", ""), path=urllib.parse.urlparse(getattr(self, "path", "")).path)

    def _send(self, status: int, body: bytes = b"", content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self._handle_read()

    def do_GET(self) -> None:
        self._handle_read()

    def _handle_read(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/health":
            payload = {"ok": True, "service": "dara-phone-bridge", "sms": True, "voice_on_vapi": True, "twilio_auth_configured": bool(_env("TWILIO_AUTH_TOKEN")), "twilio_account_configured": bool(_env("TWILIO_ACCOUNT_SID")), "relay_configured": bool(_env("RELAY_URL")), "relay_status_configured": bool(_env("RELAY_STATUS_URL")), "vapi_webhook_secret_configured": bool(_vapi_webhook_secret()), "vapi_relay_configured": bool(_vapi_relay_url())}
            self._send(200, json.dumps(payload).encode(), "application/json")
            return
        if path in {"/", ""}:
            html = "<!doctype html><meta charset='utf-8'><title>Dara phone bridge</title><body><h1>Dara phone bridge</h1><p>SMS is handled at <code>/twilio/sms</code>. Voice remains on Vapi.</p></body>"
            self._send(200, html.encode(), "text/html; charset=utf-8")
            return
        self._send(404, b'{"error":"not_found"}')

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path in SMS_PATHS:
            self._handle_sms(path)
        elif path == STATUS_PATH:
            self._handle_status(path)
        elif path == VAPI_EVENTS_PATH:
            self._handle_vapi_events()
        else:
            self._send(404, b'{"error":"not_found"}')

    def _read_form(self) -> tuple[bytes, dict[str, str], str, str]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        return raw, _parse_form(raw), self.headers.get("X-Twilio-Signature", ""), self.headers.get("Content-Type", "application/x-www-form-urlencoded")

    def _handle_sms(self, path: str) -> None:
        raw, params, signature, content_type = self._read_form()
        sid = _safe_sid(params)
        if not _validate_twilio(path, params, signature):
            _json_log("invalid_signature", endpoint="sms", path=path, message_sid=sid)
            self._send(403, b'{"error":"invalid_signature"}')
            return
        _json_log("sms_accepted", path=path, message_sid=sid, **{"from": _mask_phone(params.get("From", "")), "to": _mask_phone(params.get("To", ""))})
        relay = _env("RELAY_URL")
        if not relay:
            self._send(502, b'{"error":"relay_failed"}')
            return
        try:
            status, body, response_type = _relay_form(relay, raw, signature, content_type)
        except Exception as exc:
            _json_log("relay_failed", endpoint="sms", message_sid=sid, error=type(exc).__name__)
            self._send(502, b'{"error":"relay_failed"}')
            return
        if status >= 400:
            self._send(502, b'{"error":"relay_failed"}')
            return
        _json_log("sms_relayed", message_sid=sid, status=status)
        self._send(status, body, response_type)

    def _handle_status(self, path: str) -> None:
        raw, params, signature, content_type = self._read_form()
        sid = _safe_sid(params)
        if not _validate_twilio(path, params, signature):
            self._send(403, b'{"error":"invalid_signature"}')
            return
        _json_log("status_callback", message_sid=sid, status=params.get("MessageStatus") or params.get("SmsStatus") or "", error_code=params.get("ErrorCode", ""))
        relay = _env("RELAY_STATUS_URL")
        if relay:
            try:
                status, _, _ = _relay_form(relay, raw, signature, content_type)
                if status >= 400:
                    raise RuntimeError("bad_status")
            except Exception as exc:
                _json_log("relay_failed", endpoint="status", message_sid=sid, error=type(exc).__name__)
                self._send(502, b'{"error":"relay_failed"}')
                return
        self._send(204)

    def _read_json(self) -> tuple[bytes | None, str | None]:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            return None, "invalid_content_length"
        if length < 0:
            return None, "invalid_content_length"
        if length > MAX_VAPI_BODY_BYTES:
            return None, "body_too_large"
        raw = self.rfile.read(length) if length else b""
        try:
            json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "invalid_json"
        return raw, None

    def _handle_vapi_events(self) -> None:
        secret, relay = _vapi_webhook_secret(), _vapi_relay_url()
        if not secret or not relay:
            _json_log("vapi_config_missing", webhook_secret_configured=bool(secret), relay_configured=bool(relay))
            self._send(503, b'{"error":"vapi_not_configured"}')
            return
        if not _validate_vapi(self.headers):
            _json_log("vapi_auth_failed")
            self._send(403, b'{"error":"forbidden"}')
            return
        raw, error = self._read_json()
        if error == "body_too_large":
            self._send(413, b'{"error":"body_too_large"}')
            return
        if error:
            self._send(400, b'{"error":"invalid_json"}')
            return
        try:
            status = _relay_json(relay, raw or b"", secret)
        except Exception as exc:
            _json_log("vapi_relay_failed", error=type(exc).__name__)
            self._send(502, b'{"error":"relay_failed"}')
            return
        if status >= 400:
            self._send(502, b'{"error":"relay_failed"}')
            return
        _json_log("vapi_relayed", status=status)
        self._send(204)

def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(json.dumps({"event": "server_started", "port": PORT}), flush=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
