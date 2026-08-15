#!/usr/bin/env python3
"""Secure Twilio SMS webhook bridge for Dara Public PA."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from twilio.request_validator import RequestValidator

PORT = int(os.environ.get("PORT", "8080"))
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
PUBLIC_PA_URL = os.environ.get("PUBLIC_PA_URL", "").rstrip("/")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "https://phone.dallasclounch.com").rstrip("/")
FORWARD_PATH = os.environ.get("PUBLIC_PA_SMS_PATH", "/webhooks/twilio/sms")
EMPTY_TWIML = '<?xml version="1.0" encoding="UTF-8"?><Response></Response>'


def _mask(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) < 4:
        return "****"
    return f"***{digits[-4:]}"


def _validate_twilio(path: str, params: dict[str, str], signature: str) -> bool:
    if not TWILIO_AUTH_TOKEN or not signature:
        return False
    validator = RequestValidator(TWILIO_AUTH_TOKEN)
    url = f"{PUBLIC_HOST}{path}"
    return validator.validate(url, params, signature)


def _forward_to_public_pa(payload: dict) -> tuple[int, str]:
    if not PUBLIC_PA_URL:
        return 204, "public_pa_url_unset"
    target = f"{PUBLIC_PA_URL}{FORWARD_PATH}"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        target,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "dara-phone-bridge/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")[:500]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")[:500]
    except Exception as exc:  # noqa: BLE001
        return 599, type(exc).__name__


class Handler(BaseHTTPRequestHandler):
    server_version = "DaraPhoneBridge/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys_stderr = __import__("sys").stderr
        sys_stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            payload = {
                "ok": True,
                "service": "dara-phone-bridge",
                "sms": True,
                "voice": False,
                "public_pa_configured": bool(PUBLIC_PA_URL),
                "twilio_sid_configured": bool(TWILIO_ACCOUNT_SID),
            }
            self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
            return
        if parsed.path in {"/", ""}:
            html = (
                "<!doctype html><meta charset='utf-8'>"
                "<title>Dara Public PA</title>"
                "<body style='font-family:sans-serif;max-width:40rem;margin:4rem auto;color:#222'>"
                "<h1>Dara Public PA phone bridge</h1>"
                "<p>SMS webhook is live at <code>/sms</code>. Voice stays on Vapi.</p>"
                "</body>"
            )
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(404, b'{"error":"not_found"}', "application/json")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/sms":
            self._send(404, b'{"error":"not_found"}', "application/json")
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b""
        form = {
            key: values[-1]
            for key, values in urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items()
        }
        signature = self.headers.get("X-Twilio-Signature", "")
        if not _validate_twilio("/sms", form, signature):
            self.log_message("rejected invalid Twilio signature")
            self._send(403, b'{"error":"invalid_signature"}', "application/json")
            return
        payload = {
            "provider": "twilio",
            "account_sid": form.get("AccountSid", ""),
            "message_sid": form.get("MessageSid", ""),
            "from": form.get("From", ""),
            "to": form.get("To", ""),
            "body": form.get("Body", ""),
            "num_media": form.get("NumMedia", "0"),
        }
        status, detail = _forward_to_public_pa(payload)
        self.log_message(
            "sms sid=%s from=%s to=%s forward=%s",
            payload["message_sid"],
            _mask(payload["from"]),
            _mask(payload["to"]),
            status,
        )
        if status >= 400:
            self.log_message("forward detail=%s", detail)
        self._send(200, EMPTY_TWIML.encode("utf-8"), "text/xml")


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"dara-phone-bridge listening on {PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
