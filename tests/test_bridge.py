import json
import os
import sqlite3
import stat
from datetime import datetime, timezone
from email.message import Message
from io import BytesIO
from types import SimpleNamespace
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.error
import urllib.request

from dara_phone_bridge import (
    BridgeApp,
    BridgeHandler,
    MAX_TOOL_RESULT_CHARS,
    Settings,
    calendar_action_prompt,
    extract_calendar_event_id,
    extract_vapi_tool_calls,
    main,
    safe_vapi_event,
    speech_ready_result,
    twilio_signature,
    validate_twilio_signature,
)


PUBLIC_BASE_URL = "https://dara.example.test"
AUTH_TOKEN = "test_auth_token"
PLACEHOLDER_SMS_FROM = "+15555550100"
PLACEHOLDER_SMS_TO = "+15555550101"
PLACEHOLDER_VOICE_FORWARD_TO = "+15555550102"
PLACEHOLDER_VOICE_CALLER_ID = "+15555550103"


class FakeApp(BridgeApp):
    def __init__(self, state_db_path) -> None:
        super().__init__(
            Settings(
                public_base_url=PUBLIC_BASE_URL,
                publicpa_endpoint="http://127.0.0.1:8644/v1/chat/completions",
                publicpa_api_key="publicpa_key",
                twilio_account_sid="AC123",
                twilio_auth_token=AUTH_TOKEN,
                voice_forward_to=PLACEHOLDER_VOICE_FORWARD_TO,
                voice_caller_id=PLACEHOLDER_VOICE_CALLER_ID,
                state_db_path=state_db_path,
                vapi_webhook_secret="vapi_secret",
            )
        )
        self.sms_fields = []
        self.vapi_fields = []

    def reload_settings(self) -> None:
        return

    def start_sms_worker(self, fields):
        self.sms_fields.append(dict(fields))

    def start_vapi_worker(self, payload, call_id, event_type):
        self.vapi_fields.append((payload, call_id, event_type))


class BridgeHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_env = os.environ.copy()
        self.tempdir = tempfile.TemporaryDirectory()
        self.state_db_path = os.path.join(self.tempdir.name, "state.sqlite3")
        os.environ.update(
            {
                "PUBLIC_BASE_URL": PUBLIC_BASE_URL,
                "PUBLICPA_ENDPOINT": "http://127.0.0.1:8644/v1/chat/completions",
                "API_SERVER_KEY": "publicpa_key",
                "TWILIO_ACCOUNT_SID": "AC123",
                "TWILIO_AUTH_TOKEN": AUTH_TOKEN,
                "VOICE_FORWARD_TO": PLACEHOLDER_VOICE_FORWARD_TO,
                "VOICE_CALLER_ID": PLACEHOLDER_VOICE_CALLER_ID,
                "STATE_DB_PATH": self.state_db_path,
                "VAPI_WEBHOOK_SECRET": "vapi_secret",
            }
        )
        self.app = FakeApp(self.state_db_path)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self.old_env)
        self.tempdir.cleanup()

    def invoke(self, method, path, body=b"", headers=None):
        message = Message()
        for key, value in (headers or {}).items():
            message[key] = value
        handler = object.__new__(BridgeHandler)
        handler.rfile = BytesIO(body)
        handler.wfile = BytesIO()
        handler.headers = message
        handler.command = method
        handler.path = path
        handler.request_version = "HTTP/1.1"
        handler.requestline = f"{method} {path} HTTP/1.1"
        handler.server = SimpleNamespace(app=self.app)
        handler.client_address = ("127.0.0.1", 12345)
        handler.close_connection = True
        handler.__dict__["_BaseHTTPRequestHandler__response"] = None
        if method == "POST":
            handler.do_POST()
        elif method == "HEAD":
            handler.do_HEAD()
        else:
            handler.do_GET()
        return self.parse_response(handler.wfile.getvalue())

    def parse_response(self, raw):
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key] = value.strip()
        return status, headers, body

    def post_form(self, path, fields, signature=None):
        pairs = list(fields.items())
        body = urllib.parse.urlencode(pairs)
        if signature is None:
            signature = twilio_signature(AUTH_TOKEN, PUBLIC_BASE_URL + path, pairs)
        return self.invoke(
            "POST",
            path,
            body=body.encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(body.encode("utf-8"))),
                "X-Twilio-Signature": signature,
            },
        )

    def post_json(self, path, payload, headers=None):
        body = json.dumps(payload).encode("utf-8")
        merged_headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            **(headers or {}),
        }
        return self.invoke("POST", path, body=body, headers=merged_headers)

    def test_twilio_signature_validation_uses_sorted_form_fields(self):
        pairs = [("Body", "hello"), ("From", PLACEHOLDER_SMS_FROM), ("To", PLACEHOLDER_SMS_TO)]
        signature = twilio_signature(AUTH_TOKEN, PUBLIC_BASE_URL + "/twilio/sms", list(reversed(pairs)))

        self.assertTrue(
            validate_twilio_signature(AUTH_TOKEN, PUBLIC_BASE_URL + "/twilio/sms", pairs, signature)
        )
        self.assertFalse(
            validate_twilio_signature("wrong", PUBLIC_BASE_URL + "/twilio/sms", pairs, signature)
        )

    def test_twilio_signature_sorts_and_deduplicates_repeated_values(self):
        pairs = [("Tag", "z"), ("Body", "hello"), ("Tag", "a"), ("Tag", "z")]
        expected_pairs = [("Body", "hello"), ("Tag", "a"), ("Tag", "z")]

        signature = twilio_signature(AUTH_TOKEN, PUBLIC_BASE_URL + "/twilio/sms", pairs)

        self.assertEqual(
            signature,
            twilio_signature(AUTH_TOKEN, PUBLIC_BASE_URL + "/twilio/sms", expected_pairs),
        )
        self.assertTrue(
            validate_twilio_signature(AUTH_TOKEN, PUBLIC_BASE_URL + "/twilio/sms", pairs, signature)
        )

    def test_sms_returns_empty_twiml_immediately_and_queues_worker(self):
        fields = {
            "MessageSid": "SM111",
            "From": PLACEHOLDER_SMS_FROM,
            "To": PLACEHOLDER_SMS_TO,
            "Body": "Please call me",
        }
        started = time.monotonic()
        status, headers, body = self.post_form("/twilio/sms", fields)
        elapsed = time.monotonic() - started

        self.assertEqual(status, 200)
        self.assertLess(elapsed, 2)
        self.assertEqual(headers["Content-Type"], "text/xml; charset=utf-8")
        self.assertEqual(body, b'<?xml version="1.0" encoding="UTF-8"?><Response></Response>')
        self.assertEqual(self.app.sms_fields, [fields])
        self.assertEqual(stat.S_IMODE(os.stat(self.state_db_path).st_mode), 0o600)

    def test_duplicate_message_sid_returns_empty_twiml_without_queueing_again(self):
        fields = {
            "MessageSid": "SM111",
            "From": PLACEHOLDER_SMS_FROM,
            "To": PLACEHOLDER_SMS_TO,
            "Body": "Please call me",
        }

        first = self.post_form("/twilio/sms", fields)
        second = self.post_form("/twilio/sms", fields)

        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertEqual(second[2], b'<?xml version="1.0" encoding="UTF-8"?><Response></Response>')
        self.assertEqual(self.app.sms_fields, [fields])

    def test_voice_returns_dial_twiml(self):
        status, headers, body = self.post_form(
            "/twilio/voice",
            {"CallSid": "CA111", "From": PLACEHOLDER_SMS_FROM, "To": PLACEHOLDER_SMS_TO},
        )

        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/xml; charset=utf-8")
        self.assertIn(f'<Dial callerId="{PLACEHOLDER_VOICE_CALLER_ID}" answerOnBridge="true">'.encode(), body)
        self.assertIn(PLACEHOLDER_VOICE_FORWARD_TO.encode(), body)

    def test_voice_escapes_configured_dial_values(self):
        self.app.settings = Settings(
            public_base_url=PUBLIC_BASE_URL,
            publicpa_endpoint="http://127.0.0.1:8644/v1/chat/completions",
            publicpa_api_key="publicpa_key",
            twilio_account_sid="AC123",
            twilio_auth_token=AUTH_TOKEN,
            voice_forward_to="+15555550102&extension=<support>",
            voice_caller_id='+15555550103"',
        )

        status, _headers, body = self.post_form(
            "/twilio/voice",
            {"CallSid": "CA111", "From": PLACEHOLDER_SMS_FROM, "To": PLACEHOLDER_SMS_TO},
        )

        self.assertEqual(status, 200)
        self.assertIn(b"+15555550102&amp;extension=&lt;support&gt;", body)
        self.assertIn(b'callerId="+15555550103&quot;"', body)

    def test_voice_returns_503_safe_twiml_when_forwarding_settings_are_missing(self):
        self.app.settings = Settings(
            public_base_url=PUBLIC_BASE_URL,
            publicpa_endpoint="http://127.0.0.1:8644/v1/chat/completions",
            publicpa_api_key="publicpa_key",
            twilio_account_sid="AC123",
            twilio_auth_token=AUTH_TOKEN,
            voice_forward_to="",
            voice_caller_id=PLACEHOLDER_VOICE_CALLER_ID,
        )

        status, headers, body = self.post_form(
            "/twilio/voice",
            {"CallSid": "CA111", "From": PLACEHOLDER_SMS_FROM, "To": PLACEHOLDER_SMS_TO},
        )

        self.assertEqual(status, 503)
        self.assertEqual(headers["Content-Type"], "text/xml; charset=utf-8")
        self.assertIn(b"<Response><Say>", body)
        self.assertNotIn(b"<Dial", body)

    def test_health_returns_boolean_checks_without_values(self):
        status, _headers, body = self.invoke("GET", "/health")
        data = json.loads(body.decode("utf-8"))

        self.assertEqual(status, 200)
        self.assertEqual(data["service"], "ok")
        self.assertEqual(
            data["checks"],
            {
                "PUBLIC_BASE_URL": True,
                "PUBLICPA_ENDPOINT": True,
                "API_SERVER_KEY": True,
                "TWILIO_ACCOUNT_SID": True,
                "TWILIO_AUTH_TOKEN": True,
                "VOICE_FORWARD_TO": True,
                "VOICE_CALLER_ID": True,
                "STATE_DB": True,
                "VAPI_WEBHOOK_SECRET": True,
            },
        )
        self.assertNotIn("test_auth_token", json.dumps(data))

    def test_settings_prefers_vapi_webhook_secret_over_twilio_auth_token(self):
        missing_env_path = os.path.join(self.tempdir.name, "missing.env")
        os.environ.update(
            {
                "PUBLICPA_ENV_PATH": missing_env_path,
                "TWILIO_ENV_PATH": missing_env_path,
                "VAPI_WEBHOOK_SECRET": "vapi_secret",
                "TWILIO_AUTH_TOKEN": AUTH_TOKEN,
            }
        )

        settings = Settings.load()

        self.assertEqual(settings.vapi_webhook_secret, "vapi_secret")
        self.assertTrue(settings.health()["checks"]["VAPI_WEBHOOK_SECRET"])

    def test_settings_uses_twilio_auth_token_as_vapi_webhook_secret_fallback(self):
        missing_env_path = os.path.join(self.tempdir.name, "missing.env")
        os.environ.update(
            {
                "PUBLICPA_ENV_PATH": missing_env_path,
                "TWILIO_ENV_PATH": missing_env_path,
                "TWILIO_AUTH_TOKEN": AUTH_TOKEN,
            }
        )
        os.environ.pop("VAPI_WEBHOOK_SECRET", None)

        settings = Settings.load()
        health_json = json.dumps(settings.health())

        self.assertEqual(settings.vapi_webhook_secret, AUTH_TOKEN)
        self.assertTrue(settings.health()["checks"]["VAPI_WEBHOOK_SECRET"])
        self.assertNotIn(AUTH_TOKEN, health_json)
        self.assertNotIn("TWILIO_AUTH_TOKEN", settings.vapi_webhook_secret)

    def test_settings_reports_no_vapi_webhook_secret_when_secret_and_fallback_are_absent(self):
        missing_env_path = os.path.join(self.tempdir.name, "missing.env")
        os.environ.update(
            {
                "PUBLICPA_ENV_PATH": missing_env_path,
                "TWILIO_ENV_PATH": missing_env_path,
            }
        )
        os.environ.pop("VAPI_WEBHOOK_SECRET", None)
        os.environ.pop("TWILIO_AUTH_TOKEN", None)

        settings = Settings.load()

        self.assertEqual(settings.vapi_webhook_secret, "")
        self.assertFalse(settings.health()["checks"]["VAPI_WEBHOOK_SECRET"])

    def test_settings_validates_vapi_publicpa_action_budget(self):
        os.environ["VAPI_PUBLICPA_ACTION_BUDGET_SECONDS"] = "999"
        self.assertEqual(Settings.load().vapi_publicpa_action_budget_seconds, 88.0)

        os.environ["VAPI_PUBLICPA_ACTION_BUDGET_SECONDS"] = "-1"
        self.assertEqual(Settings.load().vapi_publicpa_action_budget_seconds, 82.0)

        os.environ["VAPI_PUBLICPA_ACTION_BUDGET_SECONDS"] = "12.5"
        self.assertEqual(Settings.load().vapi_publicpa_action_budget_seconds, 12.5)

    def test_root_and_health_support_get_and_head(self):
        root_status, root_headers, root_body = self.invoke("GET", "/")
        health_status, health_headers, health_body = self.invoke("GET", "/health")
        root_head_status, root_head_headers, root_head_body = self.invoke("HEAD", "/")
        health_head_status, health_head_headers, health_head_body = self.invoke("HEAD", "/health")

        self.assertEqual(root_status, 200)
        self.assertEqual(root_headers["Content-Type"], "text/plain; charset=utf-8")
        self.assertIn(b"Dara Phone Bridge", root_body)
        self.assertEqual(health_status, 200)
        self.assertEqual(json.loads(health_body.decode("utf-8"))["service"], "ok")
        self.assertEqual(root_head_status, 200)
        self.assertEqual(health_head_status, 200)
        self.assertEqual(root_head_headers["Content-Length"], root_headers["Content-Length"])
        self.assertEqual(health_head_headers["Content-Length"], health_headers["Content-Length"])
        self.assertEqual(root_head_body, b"")
        self.assertEqual(health_head_body, b"")

    def test_write_response_ignores_expected_client_disconnects(self):
        class BrokenWriter:
            def write(self, data):
                raise BrokenPipeError()

            def flush(self):
                raise ConnectionResetError()

        handler = object.__new__(BridgeHandler)
        handler.wfile = BrokenWriter()
        handler.request_version = "HTTP/1.1"
        handler.requestline = "POST /vapi/actions HTTP/1.1"
        handler.command = "POST"
        handler.client_address = ("127.0.0.1", 12345)

        handler.write_response(200, b"text/plain; charset=utf-8", b"ok")
        handler.flush_response()

    def test_invalid_signature_is_rejected(self):
        status, _headers, body = self.post_form(
            "/twilio/sms",
            {"MessageSid": "SM111", "From": PLACEHOLDER_SMS_FROM, "To": PLACEHOLDER_SMS_TO, "Body": "Hello"},
            signature="invalid",
        )

        self.assertEqual(status, 403)
        self.assertEqual(body, b"forbidden")
        self.assertEqual(self.app.sms_fields, [])

    def test_audit_log_records_safe_structured_events(self):
        with tempfile.TemporaryDirectory() as tempdir:
            audit_path = os.path.join(tempdir, "state", "audit.jsonl")
            os.environ["AUDIT_LOG_PATH"] = audit_path
            self.app.settings = Settings(
                public_base_url=PUBLIC_BASE_URL,
                publicpa_endpoint="http://127.0.0.1:8644/v1/chat/completions",
                publicpa_api_key="publicpa_key",
                twilio_account_sid="AC123",
                twilio_auth_token=AUTH_TOKEN,
                voice_forward_to=PLACEHOLDER_VOICE_FORWARD_TO,
                voice_caller_id=PLACEHOLDER_VOICE_CALLER_ID,
                audit_log_path=audit_path,
            )

            self.post_form(
                "/twilio/sms",
                {
                    "MessageSid": "SM111",
                    "From": PLACEHOLDER_SMS_FROM,
                    "To": PLACEHOLDER_SMS_TO,
                    "Body": "Please call me",
                },
            )
            self.post_form(
                "/twilio/status",
                {"MessageSid": "SM222", "MessageStatus": "delivered", "ErrorCode": "30001"},
            )
            self.post_form(
                "/twilio/sms",
                {
                    "MessageSid": "SM333",
                    "From": PLACEHOLDER_SMS_FROM,
                    "To": PLACEHOLDER_SMS_TO,
                    "Body": "secret body",
                },
                signature="invalid",
            )

            with open(audit_path, encoding="utf-8") as audit_file:
                lines = [json.loads(line) for line in audit_file]
            events = [line["event"] for line in lines]

        self.assertIn("sms_accepted", events)
        self.assertIn("twilio_status", events)
        self.assertIn("invalid_signature", events)
        serialized = "\n".join(json.dumps(line, sort_keys=True) for line in lines)
        self.assertNotIn("Please call me", serialized)
        self.assertNotIn("secret body", serialized)
        self.assertNotIn(PLACEHOLDER_SMS_FROM, serialized)
        self.assertNotIn(AUTH_TOKEN, serialized)

    def test_audit_log_write_failure_does_not_break_sms_webhook(self):
        with tempfile.TemporaryDirectory() as tempdir:
            audit_path = os.path.join(tempdir, "audit-dir")
            os.mkdir(audit_path)
            os.environ["AUDIT_LOG_PATH"] = audit_path
            self.app.settings = Settings(
                public_base_url=PUBLIC_BASE_URL,
                publicpa_endpoint="http://127.0.0.1:8644/v1/chat/completions",
                publicpa_api_key="publicpa_key",
                twilio_account_sid="AC123",
                twilio_auth_token=AUTH_TOKEN,
                voice_forward_to=PLACEHOLDER_VOICE_FORWARD_TO,
                voice_caller_id=PLACEHOLDER_VOICE_CALLER_ID,
                audit_log_path=audit_path,
            )

            status, _headers, body = self.post_form(
                "/twilio/sms",
                {
                    "MessageSid": "SM111",
                    "From": PLACEHOLDER_SMS_FROM,
                    "To": PLACEHOLDER_SMS_TO,
                    "Body": "Please call me",
                },
            )

        self.assertEqual(status, 200)
        self.assertEqual(body, b'<?xml version="1.0" encoding="UTF-8"?><Response></Response>')
        self.assertEqual(len(self.app.sms_fields), 1)

    def test_status_callback_logging_supports_message_and_call_fields(self):
        with tempfile.TemporaryDirectory() as tempdir:
            audit_path = os.path.join(tempdir, "audit.jsonl")
            os.environ["AUDIT_LOG_PATH"] = audit_path
            self.app.settings = Settings(
                public_base_url=PUBLIC_BASE_URL,
                publicpa_endpoint="http://127.0.0.1:8644/v1/chat/completions",
                publicpa_api_key="publicpa_key",
                twilio_account_sid="AC123",
                twilio_auth_token=AUTH_TOKEN,
                voice_forward_to=PLACEHOLDER_VOICE_FORWARD_TO,
                voice_caller_id=PLACEHOLDER_VOICE_CALLER_ID,
                audit_log_path=audit_path,
            )

            self.post_form(
                "/twilio/status",
                {
                    "MessageSid": "SM222",
                    "SmsSid": "SMLEGACY",
                    "CallSid": "CA111",
                    "MessageStatus": "delivered",
                    "SmsStatus": "sent",
                    "CallStatus": "completed",
                    "ErrorCode": "30001",
                },
            )

            with open(audit_path, encoding="utf-8") as audit_file:
                record = json.loads(audit_file.readline())

        self.assertEqual(record["event"], "twilio_status")
        self.assertEqual(record["message_sid"], "SM222")
        self.assertEqual(record["call_sid"], "CA111")
        self.assertEqual(record["message_status"], "delivered")
        self.assertEqual(record["sms_status"], "sent")
        self.assertEqual(record["call_status"], "completed")
        self.assertEqual(record["error_code"], "30001")

    def test_audit_log_records_sms_processed_and_failed(self):
        with tempfile.TemporaryDirectory() as tempdir:
            audit_path = os.path.join(tempdir, "audit.jsonl")
            os.environ["AUDIT_LOG_PATH"] = audit_path

            sent = []
            self.app.ask_publicpa = lambda sender, body, history=None: "reply"  # type: ignore[method-assign]
            self.app.send_twilio_message = (  # type: ignore[method-assign]
                lambda to_number, from_number, body: sent.append((to_number, from_number, body))
            )
            self.app.process_sms(
                {
                    "MessageSid": "SM111",
                    "From": PLACEHOLDER_SMS_FROM,
                    "To": PLACEHOLDER_SMS_TO,
                    "Body": "Please call me",
                }
            )

            def failing_publicpa(sender, body, history=None):
                raise RuntimeError("boom")

            self.app.ask_publicpa = failing_publicpa  # type: ignore[method-assign]
            self.app.process_sms(
                {
                    "MessageSid": "SM222",
                    "From": PLACEHOLDER_SMS_FROM,
                    "To": PLACEHOLDER_SMS_TO,
                    "Body": "secret body",
                }
            )

            with open(audit_path, encoding="utf-8") as audit_file:
                lines = [json.loads(line) for line in audit_file]

        events = [line["event"] for line in lines]
        serialized = "\n".join(json.dumps(line, sort_keys=True) for line in lines)
        self.assertEqual(sent, [(PLACEHOLDER_SMS_FROM, PLACEHOLDER_SMS_TO, "reply")])
        self.assertIn("sms_processed", events)
        self.assertIn("sms_failed", events)
        self.assertNotIn("Please call me", serialized)
        self.assertNotIn("secret body", serialized)
        self.assertNotIn(PLACEHOLDER_SMS_FROM, serialized)

    def test_send_twilio_message_sets_status_callback(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"{}"

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse()

        old_urlopen = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        try:
            self.app.send_twilio_message(PLACEHOLDER_SMS_FROM, PLACEHOLDER_SMS_TO, "reply")
        finally:
            urllib.request.urlopen = old_urlopen

        form = dict(urllib.parse.parse_qsl(captured["request"].data.decode("utf-8")))
        self.assertEqual(form["To"], PLACEHOLDER_SMS_FROM)
        self.assertEqual(form["From"], PLACEHOLDER_SMS_TO)
        self.assertEqual(form["Body"], "reply")
        self.assertEqual(form["StatusCallback"], PUBLIC_BASE_URL + "/twilio/status")

    def test_status_callback_persists_delivery_status(self):
        self.post_form(
            "/twilio/status",
            {"MessageSid": "SM222", "MessageStatus": "delivered", "ErrorCode": "30001"},
        )

        with sqlite3.connect(self.state_db_path) as db:
            row = db.execute(
                "SELECT message_status, error_code FROM twilio_statuses WHERE sid = ?",
                ("SM222",),
            ).fetchone()

        self.assertEqual(row, ("delivered", "30001"))

    def test_sms_history_is_bounded_and_included_in_publicpa_prompt(self):
        captured = {}
        sent = []

        def fake_call_publicpa(payload):
            captured["payload"] = payload
            return "x" * 1600

        self.app.call_publicpa = fake_call_publicpa  # type: ignore[method-assign]
        self.app.send_twilio_message = (  # type: ignore[method-assign]
            lambda to_number, from_number, body: sent.append((to_number, from_number, body))
        )
        for index in range(14):
            self.app.process_sms(
                {
                    "MessageSid": f"SM{index}",
                    "From": PLACEHOLDER_SMS_FROM,
                    "To": PLACEHOLDER_SMS_TO,
                    "Body": f"inbound {index}",
                }
            )

        history_text = captured["payload"]["messages"][1]["content"]
        self.assertIn("Recent conversation, oldest to newest", history_text)
        self.assertIn("inbound 13", history_text)
        self.assertNotIn("inbound 0", history_text)
        self.assertEqual(len(sent[-1][2]), 1500)
        with sqlite3.connect(self.state_db_path) as db:
            count = db.execute(
                "SELECT count(*) FROM sms_turns WHERE peer = ?",
                (PLACEHOLDER_SMS_FROM,),
            ).fetchone()[0]
        self.assertEqual(count, 12)

    def test_vapi_events_rejects_invalid_secret_and_accepts_bearer_secret(self):
        payload = {"type": "end-of-call-report", "call": {"id": "call_1"}}

        invalid_status, _headers, invalid_body = self.post_json(
            "/vapi/events",
            payload,
            headers={"x-vapi-secret": "wrong"},
        )
        valid_status, _headers, valid_body = self.post_json(
            "/vapi/events",
            payload,
            headers={"Authorization": "Bearer vapi_secret"},
        )

        self.assertEqual(invalid_status, 403)
        self.assertEqual(invalid_body, b"forbidden")
        self.assertEqual(valid_status, 204)
        self.assertEqual(valid_body, b"")
        self.assertEqual(len(self.app.vapi_fields), 1)

    def test_vapi_events_requires_valid_json(self):
        status, _headers, body = self.invoke(
            "POST",
            "/vapi/events",
            body=b"{",
            headers={
                "Content-Type": "application/json",
                "Content-Length": "1",
                "x-vapi-secret": "vapi_secret",
            },
        )

        self.assertEqual(status, 400)
        self.assertEqual(body, b"invalid json")

    def test_vapi_action_rejects_oversized_json_payload(self):
        status, _headers, body = self.invoke(
            "POST",
            "/vapi/tools",
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(256 * 1024 + 1),
                "x-vapi-secret": "vapi_secret",
            },
        )

        self.assertEqual(status, 413)
        self.assertEqual(body, b"payload too large")

    def test_vapi_events_deduplicates_by_call_id_and_event_type(self):
        payload = {"type": "end-of-call-report", "call": {"id": "call_1"}}

        first = self.post_json("/vapi/events", payload, headers={"x-vapi-secret": "vapi_secret"})
        second = self.post_json("/vapi/events", payload, headers={"x-vapi-secret": "vapi_secret"})

        self.assertEqual(first[0], 204)
        self.assertEqual(second[0], 204)
        self.assertEqual(len(self.app.vapi_fields), 1)

    def test_vapi_events_returns_immediately_before_async_processing_finishes(self):
        done = threading.Event()

        def slow_process(payload, call_id, event_type):
            time.sleep(0.25)
            done.set()

        self.app.process_vapi_event = slow_process  # type: ignore[method-assign]
        self.app.start_vapi_worker = BridgeApp.start_vapi_worker.__get__(self.app, FakeApp)  # type: ignore[method-assign]
        started = time.monotonic()
        status, _headers, body = self.post_json(
            "/vapi/events",
            {"type": "end-of-call-report", "call": {"id": "call_async"}},
            headers={"x-vapi-secret": "vapi_secret"},
        )
        elapsed = time.monotonic() - started

        self.assertEqual(status, 204)
        self.assertEqual(body, b"")
        self.assertLess(elapsed, 0.24)
        self.assertTrue(done.wait(1))

    def test_vapi_safe_event_processing_omits_transcript_and_recording_urls(self):
        captured = {}
        payload = {
            "type": "end-of-call-report",
            "call": {
                "id": "call_1",
                "type": "inboundPhoneCall",
                "status": "ended",
                "endedReason": "customer-ended-call",
                "customer": {"number": PLACEHOLDER_SMS_FROM},
            },
            "summary": "Customer asked for a follow-up.",
            "structuredData": {"appointmentConfirmed": False},
            "assistantOverrides": {"variableValues": {"source": "phone"}},
            "transcript": "do not send",
            "recordingUrl": "https://recording.example.test/file.wav",
        }

        self.app.call_publicpa = lambda publicpa_payload: captured.setdefault("payload", publicpa_payload) or ""  # type: ignore[method-assign]
        self.app.process_vapi_event(payload, "call_1", "end-of-call-report")

        serialized = json.dumps(captured["payload"], sort_keys=True)
        self.assertIn("completed live phone call report", serialized)
        self.assertIn("Customer asked for a follow-up.", serialized)
        self.assertIn("appointmentConfirmed", serialized)
        self.assertIn(PLACEHOLDER_SMS_FROM, serialized)
        self.assertNotIn("do not send", serialized)
        self.assertNotIn("recording.example.test", serialized)

        safe = safe_vapi_event(payload, "call_1", "end-of-call-report")
        self.assertEqual(safe["call"]["id"], "call_1")
        self.assertNotIn("transcript", safe)
        self.assertNotIn("recordingUrl", safe)

    def test_vapi_tool_endpoint_requires_auth_and_returns_tool_result(self):
        captured = {}

        def fake_call_publicpa(payload):
            captured["payload"] = payload
            return json.dumps({"speech": "Tuesday at 9 AM is open.", "calendar_event_id": "evt_123"})

        self.app.call_publicpa = fake_call_publicpa  # type: ignore[method-assign]
        payload = {
            "message": {
                "call": {"id": "call_1"},
                "toolCalls": [
                    {
                        "id": "tool_1",
                        "function": {
                            "name": "checkAvailability",
                            "arguments": json.dumps({"window": "Tuesday morning"}),
                        },
                    }
                ],
            }
        }

        denied = self.post_json("/vapi/tools", payload, headers={"x-vapi-secret": "wrong"})
        allowed = self.post_json("/vapi/tools", payload, headers={"x-vapi-secret": "vapi_secret"})

        self.assertEqual(denied[0], 403)
        self.assertEqual(allowed[0], 200)
        data = json.loads(allowed[2].decode("utf-8"))
        self.assertEqual(data["results"][0]["toolCallId"], "tool_1")
        self.assertEqual(data["results"][0]["result"], "Tuesday at 9 AM is open.")
        self.assertEqual(data["results"][0]["calendar_event_id"], "evt_123")
        prompt = json.dumps(captured["payload"])
        self.assertIn("Use Google Calendar", prompt)
        self.assertIn("check_availability", prompt)

    def test_calendar_operation_prompts_require_google_calendar_and_concise_results(self):
        for operation in (
            "check_availability",
            "create_booking",
            "reschedule_booking",
            "cancel_booking",
            "read_back",
        ):
            messages = calendar_action_prompt(operation, {"name": "Ada"}, "call_1", "act_1", {})
            serialized = json.dumps(messages)
            self.assertIn("Use Google Calendar", serialized)
            self.assertIn("concise speech-safe", serialized)
            self.assertIn(operation, serialized)

    def test_calendar_prompt_includes_authoritative_arizona_clock_context(self):
        messages = calendar_action_prompt(
            "check_availability",
            {"date": "2024-08-17", "spoken_date": "Monday"},
            "call_1",
            "act_1",
            {},
            current_time=datetime(2026, 8, 17, 15, 30, tzinfo=timezone.utc),
        )
        serialized = json.dumps(messages)
        user_payload = json.loads(messages[1]["content"])
        clock = user_payload["authoritative_calendar_clock"]

        self.assertIn("America/Phoenix", serialized)
        self.assertIn("2026-08-17T08:30:00-07:00", serialized)
        self.assertEqual(clock["timezone"], "America/Phoenix")
        self.assertEqual(clock["current_date"], "2026-08-17")
        self.assertEqual(clock["current_weekday"], "Monday")

    def test_calendar_prompt_instructs_publicpa_to_clarify_stale_machine_guessed_dates(self):
        messages = calendar_action_prompt(
            "create_booking",
            {"date": "2024-08-19", "spoken_date": "Monday"},
            "call_1",
            "act_1",
            {},
            current_time=datetime(2026, 8, 17, 8, 30),
        )
        serialized = json.dumps(messages)

        self.assertIn("Resolve all caller relative date phrases against this live America/Phoenix clock", serialized)
        self.assertIn("obviously stale, out-of-year, or contradictory machine-guessed ISO date", serialized)
        self.assertIn("ask for clarification instead of reading or writing the wrong date", serialized)

    def test_vapi_tool_parser_accepts_envelope_variants(self):
        payload = {
            "callId": "call_top",
            "toolCallList": [
                {
                    "toolCallId": "tool_1",
                    "function": {"name": "createBooking", "arguments": "{\"start\":\"9\"}"},
                },
                {
                    "id": "tool_2",
                    "name": "cancel_booking",
                    "parameters": {"calendar_event_id": "evt_1"},
                    "callId": "call_nested",
                },
            ],
        }

        calls = extract_vapi_tool_calls(payload)

        self.assertEqual([call.action_id for call in calls], ["tool_1", "tool_2"])
        self.assertEqual([call.name for call in calls], ["create_booking", "cancel_booking"])
        self.assertEqual(calls[0].arguments["start"], "9")
        self.assertEqual(calls[1].call_id, "call_nested")

    def test_vapi_tool_duplicate_replay_returns_stored_result_without_publicpa_call(self):
        calls = []

        def fake_call_publicpa(payload):
            calls.append(payload)
            return "Booked. calendar_event_id: evt_1"

        self.app.call_publicpa = fake_call_publicpa  # type: ignore[method-assign]
        payload = {
            "callId": "call_1",
            "toolCalls": [{"id": "tool_1", "name": "create_booking", "arguments": {"start": "9"}}],
        }

        first = self.post_json("/vapi/actions", payload, headers={"Authorization": "Bearer vapi_secret"})
        second = self.post_json("/vapi/actions", payload, headers={"Authorization": "Bearer vapi_secret"})

        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertEqual(json.loads(first[2].decode("utf-8")), json.loads(second[2].decode("utf-8")))
        self.assertEqual(len(calls), 1)

    def test_concurrent_vapi_tool_duplicates_wait_for_single_stored_result(self):
        calls = []
        calls_lock = threading.Lock()
        entered = threading.Event()
        waiter_entered = threading.Event()
        release = threading.Event()
        payload = {
            "callId": "call_1",
            "toolCalls": [{"id": "tool_race", "name": "create_booking", "arguments": {"start": "9"}}],
        }
        results = []
        errors = []

        def fake_call_publicpa(publicpa_payload):
            with calls_lock:
                calls.append(publicpa_payload)
            entered.set()
            self.assertTrue(release.wait(5))
            return 'Booked. {"calendar_event_id":"evt_race"}'

        def execute():
            try:
                results.append(self.app.execute_vapi_tools(payload))
            except Exception as exc:  # pragma: no cover - reported through assertion below.
                errors.append(exc)

        self.app.call_publicpa = fake_call_publicpa  # type: ignore[method-assign]
        original_wait = self.app.wait_for_vapi_action_result

        def wait_for_result(call):
            waiter_entered.set()
            return original_wait(call)

        self.app.wait_for_vapi_action_result = wait_for_result  # type: ignore[method-assign]

        first = threading.Thread(target=execute)
        second = threading.Thread(target=execute)
        first.start()
        self.assertTrue(entered.wait(5))
        second.start()
        self.assertTrue(waiter_entered.wait(5))
        self.assertEqual(len(calls), 1)
        release.set()
        first.join(5)
        second.join(5)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]["results"][0]["toolCallId"], "tool_race")
        self.assertEqual(results[0]["results"][0]["calendar_event_id"], "evt_race")

        with sqlite3.connect(self.state_db_path) as db:
            processed = db.execute(
                "SELECT COUNT(*) FROM vapi_action_results WHERE action_id = ?",
                ("tool_race",),
            ).fetchone()[0]
            claims = db.execute(
                "SELECT COUNT(*) FROM vapi_action_claims WHERE action_id = ?",
                ("tool_race",),
            ).fetchone()[0]

        self.assertEqual(processed, 1)
        self.assertEqual(claims, 0)

    def test_stale_vapi_action_claim_recovers_and_executes_once(self):
        self.app.state.ensure_ready()
        expired = time.time() - 5
        with sqlite3.connect(self.state_db_path) as db:
            db.execute(
                """
                INSERT INTO vapi_action_claims(
                    action_id, call_id, tool_name, request_json,
                    claimed_at, lease_expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ("tool_stale", "call_1", "create_booking", "{}", expired - 10, expired, expired),
            )
        calls = []
        self.app.call_publicpa = lambda payload: calls.append(payload) or 'Booked. {"calendar_event_id":"evt_stale"}'  # type: ignore[method-assign]

        response = self.app.execute_vapi_tools(
            {
                "callId": "call_1",
                "toolCalls": [{"id": "tool_stale", "name": "create_booking", "arguments": {"start": "9"}}],
            }
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(response["results"][0]["toolCallId"], "tool_stale")
        self.assertEqual(response["results"][0]["calendar_event_id"], "evt_stale")
        with sqlite3.connect(self.state_db_path) as db:
            claims = db.execute(
                "SELECT COUNT(*) FROM vapi_action_claims WHERE action_id = ?",
                ("tool_stale",),
            ).fetchone()[0]
        self.assertEqual(claims, 0)

    def test_publicpa_and_twilio_transient_errors_are_retried(self):
        attempts = {"publicpa": 0, "twilio": 0}
        old_urlopen = urllib.request.urlopen
        old_sleep = time.sleep

        class FakeResponse:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return self.body

        def fake_urlopen(request, timeout):
            url = request.full_url
            if "127.0.0.1" in url:
                attempts["publicpa"] += 1
                if attempts["publicpa"] == 1:
                    raise urllib.error.URLError("temporary")
                return FakeResponse(b'{"choices":[{"message":{"content":"ok"}}]}')
            attempts["twilio"] += 1
            if attempts["twilio"] == 1:
                raise urllib.error.URLError("temporary")
            return FakeResponse(b'{"sid":"SMOUT"}')

        urllib.request.urlopen = fake_urlopen
        time.sleep = lambda seconds: None  # type: ignore[assignment]
        try:
            self.assertEqual(self.app.call_publicpa({"messages": []}), "ok")
            self.assertEqual(self.app.send_twilio_message("+1", "+2", "body"), "SMOUT")
        finally:
            urllib.request.urlopen = old_urlopen
            time.sleep = old_sleep

        self.assertEqual(attempts, {"publicpa": 2, "twilio": 2})

    def test_publicpa_total_budget_caps_per_attempt_timeout(self):
        old_urlopen = urllib.request.urlopen
        old_sleep = time.sleep
        old_monotonic = time.monotonic
        clock = {"now": 1000.0}
        timeouts = []

        def fake_urlopen(request, timeout):
            timeouts.append(timeout)
            clock["now"] += timeout
            raise urllib.error.URLError("temporary")

        urllib.request.urlopen = fake_urlopen
        time.sleep = lambda seconds: clock.__setitem__("now", clock["now"] + seconds)  # type: ignore[assignment]
        time.monotonic = lambda: clock["now"]  # type: ignore[assignment]
        try:
            with self.assertRaises(TimeoutError):
                self.app.call_publicpa({"messages": []}, total_budget_seconds=82)
        finally:
            urllib.request.urlopen = old_urlopen
            time.sleep = old_sleep
            time.monotonic = old_monotonic

        self.assertEqual(timeouts, [60.0, 21.75])

    def test_publicpa_budgeted_retry_uses_remaining_time_after_early_failure(self):
        old_urlopen = urllib.request.urlopen
        old_sleep = time.sleep
        old_monotonic = time.monotonic
        clock = {"now": 1000.0}
        timeouts = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"choices":[{"message":{"content":"ok"}}]}'

        def fake_urlopen(request, timeout):
            timeouts.append(timeout)
            if len(timeouts) == 1:
                raise urllib.error.URLError("temporary")
            return FakeResponse()

        urllib.request.urlopen = fake_urlopen
        time.sleep = lambda seconds: clock.__setitem__("now", clock["now"] + seconds)  # type: ignore[assignment]
        time.monotonic = lambda: clock["now"]  # type: ignore[assignment]
        try:
            self.assertEqual(self.app.call_publicpa({"messages": []}, total_budget_seconds=82), "ok")
        finally:
            urllib.request.urlopen = old_urlopen
            time.sleep = old_sleep
            time.monotonic = old_monotonic

        self.assertEqual(timeouts, [60.0, 60.0])

    def test_vapi_action_claim_and_wait_budgets_use_vapi_lifetime(self):
        self.app.settings = Settings(
            public_base_url=PUBLIC_BASE_URL,
            publicpa_endpoint="http://127.0.0.1:8644/v1/chat/completions",
            publicpa_api_key="publicpa_key",
            twilio_account_sid="AC123",
            twilio_auth_token=AUTH_TOKEN,
            voice_forward_to=PLACEHOLDER_VOICE_FORWARD_TO,
            voice_caller_id=PLACEHOLDER_VOICE_CALLER_ID,
            state_db_path=self.state_db_path,
            vapi_publicpa_action_budget_seconds=0.25,
            vapi_webhook_secret="vapi_secret",
        )
        captured = {}
        original_claim = self.app.state.claim_action_execution

        def fake_claim(action_id, call_id, tool_name, request_payload, lease_seconds):
            captured["lease_seconds"] = lease_seconds
            return original_claim(action_id, call_id, tool_name, request_payload, lease_seconds)

        self.app.state.claim_action_execution = fake_claim  # type: ignore[method-assign]
        self.app.execute_vapi_tools(
            {"callId": "call_1", "toolCalls": [{"id": "tool_unsupported", "name": "unsupported"}]}
        )

        self.assertEqual(captured["lease_seconds"], 0.25)

        old_sleep = time.sleep
        old_monotonic = time.monotonic
        clock = {"now": 2000.0}
        sleeps = []
        call = extract_vapi_tool_calls(
            {"callId": "call_1", "toolCalls": [{"id": "tool_wait", "name": "create_booking"}]}
        )[0]

        time.monotonic = lambda: clock["now"]  # type: ignore[assignment]

        def fake_sleep(seconds):
            sleeps.append(seconds)
            clock["now"] += seconds

        time.sleep = fake_sleep  # type: ignore[assignment]
        try:
            result = self.app.wait_for_vapi_action_result(call)
        finally:
            time.sleep = old_sleep
            time.monotonic = old_monotonic

        self.assertFalse(result["success"])
        self.assertLessEqual(sum(sleeps), 0.250001)
        self.assertAlmostEqual(sleeps[-1], 0.05)

    def test_correlations_link_action_message_provider_status_and_calendar_event(self):
        self.app.call_publicpa = lambda payload: 'Booked. {"calendar_event_id":"evt_1"}'  # type: ignore[method-assign]

        self.post_json(
            "/vapi/tools",
            {"callId": "call_1", "toolCalls": [{"id": "tool_1", "name": "create_booking"}]},
            headers={"x-vapi-secret": "vapi_secret"},
        )
        self.app.state.save_correlation(message_sid="SMIN", provider_sid="SMOUT")
        self.post_form("/twilio/status", {"MessageSid": "SMOUT", "MessageStatus": "delivered"})

        with sqlite3.connect(self.state_db_path) as db:
            action_row = db.execute(
                "SELECT call_id, action_id, calendar_event_id FROM correlations WHERE action_id = ?",
                ("tool_1",),
            ).fetchone()
            sms_row = db.execute(
                "SELECT message_sid, provider_sid, provider_status FROM correlations WHERE provider_sid = ?",
                ("SMOUT",),
            ).fetchone()

        self.assertEqual(action_row, ("call_1", "tool_1", "evt_1"))
        self.assertEqual(sms_row, ("SMIN", "SMOUT", "delivered"))

    def test_vapi_calendar_actions_extract_trailing_embedded_json_event_id(self):
        responses = {
            "create_booking": 'Booked for Tuesday at 9 AM. {"calendar_event_id":"evt_create_123"}',
            "reschedule_booking": 'Moved to Wednesday at 10 AM. {"calendar_event_id":"evt_reschedule_123"}',
            "cancel_booking": 'Cancelled the Wednesday booking. {"calendar_event_id":"evt_cancel_123"}',
        }

        def fake_call_publicpa(payload):
            content = json.loads(payload["messages"][1]["content"])
            return responses[content["operation"]]

        self.app.call_publicpa = fake_call_publicpa  # type: ignore[method-assign]

        payload = {
            "callId": "call_1",
            "toolCalls": [
                {"id": f"tool_{name}", "name": name, "arguments": {"calendar_event_id": "evt_old"}}
                for name in responses
            ],
        }

        status, _, body = self.post_json("/vapi/actions", payload, headers={"x-vapi-secret": "vapi_secret"})

        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(len(data["results"]), 3)
        for result in data["results"]:
            self.assertNotIn("{", result["result"])
            operation = result["toolCallId"].removeprefix("tool_")
            self.assertEqual(result["calendar_event_id"], responses[operation].split('"')[3])

        with sqlite3.connect(self.state_db_path) as db:
            rows = db.execute(
                "SELECT action_id, calendar_event_id FROM correlations ORDER BY action_id",
            ).fetchall()

        self.assertEqual(
            rows,
            [
                ("tool_cancel_booking", "evt_cancel_123"),
                ("tool_create_booking", "evt_create_123"),
                ("tool_reschedule_booking", "evt_reschedule_123"),
            ],
        )

    def test_vapi_read_back_uses_persisted_confirmed_result_without_publicpa_call(self):
        self.app.state.ensure_ready()
        self.app.state.save_call_context(
            "call_1",
            {
                "calendar_event_id": "evt_confirmed_123",
                "last_successful_calendar_result": "I confirmed your booking for Tuesday at 9 AM.",
            },
        )
        calls = []
        self.app.call_publicpa = lambda payload: calls.append(payload) or "should not be used"  # type: ignore[method-assign]

        response = self.app.execute_vapi_tools(
            {"callId": "call_1", "toolCalls": [{"id": "tool_read", "name": "read_back"}]}
        )

        result = response["results"][0]
        self.assertEqual(calls, [])
        self.assertEqual(result["toolCallId"], "tool_read")
        self.assertEqual(result["calendar_event_id"], "evt_confirmed_123")
        self.assertEqual(result["result"], "I confirmed your booking for Tuesday at 9 AM.")
        self.assertTrue(result["result"].endswith("."))

    def test_vapi_mutating_action_without_event_id_invalidates_local_read_back_cache(self):
        self.app.state.ensure_ready()
        self.app.state.save_call_context(
            "call_1",
            {
                "calendar_event_id": "evt_old_123",
                "last_successful_calendar_result": "I confirmed your old booking for Monday at 8 AM.",
            },
        )
        calls = []

        def fake_call_publicpa(payload):
            calls.append(payload)
            content = json.loads(payload["messages"][1]["content"])
            if content["operation"] == "create_booking":
                return "I confirmed your new booking for Tuesday at 9 AM."
            return 'I found the new booking for Tuesday at 9 AM. {"calendar_event_id":"evt_new_123"}'

        self.app.call_publicpa = fake_call_publicpa  # type: ignore[method-assign]

        create_response = self.app.execute_vapi_tools(
            {"callId": "call_1", "toolCalls": [{"id": "tool_create", "name": "create_booking"}]}
        )
        read_response = self.app.execute_vapi_tools(
            {"callId": "call_1", "toolCalls": [{"id": "tool_read", "name": "read_back"}]}
        )

        self.assertEqual(create_response["results"][0]["result"], "I confirmed your new booking for Tuesday at 9 AM.")
        self.assertNotIn("calendar_event_id", create_response["results"][0])
        self.assertEqual(len(calls), 2)
        self.assertEqual(read_response["results"][0]["calendar_event_id"], "evt_new_123")
        self.assertEqual(
            read_response["results"][0]["result"],
            "I found the new booking for Tuesday at 9 AM.",
        )

    def test_vapi_clarification_does_not_pair_with_old_event_id_for_local_read_back(self):
        self.app.state.ensure_ready()
        self.app.state.save_call_context(
            "call_1",
            {
                "calendar_event_id": "evt_old",
                "last_successful_calendar_result": "I confirmed your old booking for Monday at 8 AM.",
                "last_successful_calendar_tool": "create_booking",
            },
        )
        calls = []

        def fake_call_publicpa(payload):
            calls.append(payload)
            content = json.loads(payload["messages"][1]["content"])
            if content["operation"] == "create_booking":
                return "Which Monday did you mean?"
            return 'I found the current booking for Tuesday at 9 AM. {"calendar_event_id":"evt_new"}'

        self.app.call_publicpa = fake_call_publicpa  # type: ignore[method-assign]

        create_response = self.app.execute_vapi_tools(
            {"callId": "call_1", "toolCalls": [{"id": "tool_create", "name": "create_booking"}]}
        )
        read_response = self.app.execute_vapi_tools(
            {"callId": "call_1", "toolCalls": [{"id": "tool_read", "name": "read_back"}]}
        )

        self.assertEqual(create_response["results"][0]["result"], "Which Monday did you mean?")
        self.assertNotIn("calendar_event_id", create_response["results"][0])
        self.assertEqual(len(calls), 2)
        self.assertEqual(read_response["results"][0]["calendar_event_id"], "evt_new")
        self.assertEqual(
            read_response["results"][0]["result"],
            "I found the current booking for Tuesday at 9 AM.",
        )
        self.assertNotEqual(read_response["results"][0]["result"], "Which Monday did you mean?")
        context = self.app.state.call_context("call_1")
        self.assertEqual(context["last_successful_calendar_result"], "I found the current booking for Tuesday at 9 AM.")
        self.assertEqual(context["calendar_event_id"], "evt_new")

    def test_vapi_reschedule_without_response_id_does_not_cache_existing_event_id(self):
        self.app.state.ensure_ready()
        self.app.state.save_call_context("call_1", {"calendar_event_id": "evt_existing_123"})
        calls = []

        def fake_call_publicpa(payload):
            calls.append(payload)
            content = json.loads(payload["messages"][1]["content"])
            if content["operation"] == "reschedule_booking":
                return "I moved your booking to Wednesday at 10 AM."
            return 'I found your booking on Wednesday at 10 AM. {"calendar_event_id":"evt_existing_123"}'

        self.app.call_publicpa = fake_call_publicpa  # type: ignore[method-assign]

        response = self.app.execute_vapi_tools(
            {
                "callId": "call_1",
                "toolCalls": [
                    {
                        "id": "tool_reschedule",
                        "name": "reschedule_booking",
                        "arguments": {"calendar_event_id": "evt_existing_123"},
                    }
                ],
            }
        )

        self.assertEqual(response["results"][0]["calendar_event_id"], "evt_existing_123")
        context = self.app.state.call_context("call_1")
        self.assertEqual(context["calendar_event_id"], "")
        self.assertEqual(context["last_successful_calendar_result"], "")

        read_response = self.app.execute_vapi_tools(
            {"callId": "call_1", "toolCalls": [{"id": "tool_read", "name": "read_back"}]}
        )

        self.assertEqual(len(calls), 2)
        self.assertEqual(read_response["results"][0]["calendar_event_id"], "evt_existing_123")
        self.assertEqual(read_response["results"][0]["result"], "I found your booking on Wednesday at 10 AM.")

    def test_speech_ready_result_never_returns_raw_json_only_payload(self):
        result = speech_ready_result("create_booking", '{"calendar_event_id":"evt_123"}')

        self.assertEqual(result, "The calendar action completed, but I do not have any details to read back.")
        self.assertNotIn("{", result)

    def test_speech_ready_result_adds_punctuation_at_exact_limit_without_exceeding_it(self):
        result = speech_ready_result("create_booking", "A" * MAX_TOOL_RESULT_CHARS)

        self.assertEqual(len(result), MAX_TOOL_RESULT_CHARS)
        self.assertTrue(result.endswith("."))

    def test_speech_ready_result_preserves_terminal_punctuation_at_exact_limit(self):
        result = speech_ready_result("create_booking", ("A" * (MAX_TOOL_RESULT_CHARS - 1)) + "?")

        self.assertEqual(len(result), MAX_TOOL_RESULT_CHARS)
        self.assertTrue(result.endswith("?"))

    def test_vapi_action_latency_telemetry_includes_total_and_publicpa_elapsed_ms(self):
        with tempfile.TemporaryDirectory() as tempdir:
            audit_path = os.path.join(tempdir, "audit.jsonl")
            os.environ["AUDIT_LOG_PATH"] = audit_path
            self.app.call_publicpa = lambda payload: 'Booked for Tuesday at 9 AM. {"calendar_event_id":"evt_1"}'  # type: ignore[method-assign]

            response = self.app.execute_vapi_tools(
                {
                    "callId": "call_1",
                    "toolCalls": [{"id": "tool_1", "name": "create_booking", "arguments": {"start": "9"}}],
                }
            )

            with open(audit_path, encoding="utf-8") as audit_file:
                records = [json.loads(line) for line in audit_file if line.strip()]

        self.assertEqual(response["results"][0]["calendar_event_id"], "evt_1")
        processed = [record for record in records if record["event"] == "vapi_action_processed"]
        self.assertEqual(len(processed), 1)
        self.assertIn("total_elapsed_ms", processed[0])
        self.assertIn("publicpa_elapsed_ms", processed[0])
        self.assertIsInstance(processed[0]["total_elapsed_ms"], int)
        self.assertIsInstance(processed[0]["publicpa_elapsed_ms"], int)
        self.assertGreaterEqual(processed[0]["total_elapsed_ms"], processed[0]["publicpa_elapsed_ms"])

    def test_vapi_read_back_fast_path_emits_zero_publicpa_elapsed_ms(self):
        self.app.state.ensure_ready()
        self.app.state.save_call_context(
            "call_1",
            {
                "calendar_event_id": "evt_confirmed_123",
                "last_successful_calendar_result": "I confirmed your booking for Tuesday at 9 AM.",
            },
        )
        with tempfile.TemporaryDirectory() as tempdir:
            audit_path = os.path.join(tempdir, "audit.jsonl")
            os.environ["AUDIT_LOG_PATH"] = audit_path

            self.app.execute_vapi_tools(
                {"callId": "call_1", "toolCalls": [{"id": "tool_read", "name": "read_back"}]}
            )

            with open(audit_path, encoding="utf-8") as audit_file:
                records = [json.loads(line) for line in audit_file if line.strip()]

        processed = [record for record in records if record["event"] == "vapi_action_processed"]
        self.assertEqual(processed[0]["outcome"], "local_read_back")
        self.assertEqual(processed[0]["publicpa_elapsed_ms"], 0)
        self.assertIn("total_elapsed_ms", processed[0])

    def test_vapi_action_error_telemetry_includes_publicpa_elapsed_ms(self):
        with tempfile.TemporaryDirectory() as tempdir:
            audit_path = os.path.join(tempdir, "audit.jsonl")
            os.environ["AUDIT_LOG_PATH"] = audit_path

            def failing_publicpa(payload):
                raise TimeoutError("publicpa timed out")

            self.app.call_publicpa = failing_publicpa  # type: ignore[method-assign]

            response = self.app.execute_vapi_tools(
                {
                    "callId": "call_1",
                    "toolCalls": [{"id": "tool_1", "name": "create_booking", "arguments": {"start": "9"}}],
                }
            )

            with open(audit_path, encoding="utf-8") as audit_file:
                records = [json.loads(line) for line in audit_file if line.strip()]

        self.assertFalse(response["results"][0]["success"])
        self.assertEqual(response["results"][0]["toolCallId"], "tool_1")
        processed = [record for record in records if record["event"] == "vapi_action_processed"]
        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0]["call_id"], "call_1")
        self.assertEqual(processed[0]["action_id"], "tool_1")
        self.assertEqual(processed[0]["tool_name"], "create_booking")
        self.assertEqual(processed[0]["error"], "TimeoutError")
        self.assertEqual(processed[0]["outcome"], "error")
        self.assertIsInstance(processed[0]["total_elapsed_ms"], int)
        self.assertIsInstance(processed[0]["publicpa_elapsed_ms"], int)
        self.assertEqual(processed[0]["publicpa_budget_ms"], 82000)
        self.assertGreaterEqual(processed[0]["total_elapsed_ms"], processed[0]["publicpa_elapsed_ms"])

    def test_calendar_event_id_parser_validates_json_field_values(self):
        self.assertEqual(
            extract_calendar_event_id('Booked. {"calendar_event_id":"evt_valid-123.abc"}'),
            "evt_valid-123.abc",
        )
        self.assertEqual(extract_calendar_event_id('Booked. {"calendar_event_id":"evt bad"}'), "")
        self.assertEqual(extract_calendar_event_id('Booked. {"calendar_event_id":"evt/unsafe"}'), "")

    def test_call_context_and_follow_up_queue_survive_restart_and_execute(self):
        self.app.state.ensure_ready()
        self.app.state.save_call_context("call_1", {"calendar_event_id": "evt_1"})
        self.app.enqueue_follow_up(time.time() - 1, "calendar_check", {"call_id": "call_1"})

        restarted = FakeApp(self.state_db_path)
        calls = []
        restarted.call_publicpa = lambda payload: calls.append(payload) or "done"  # type: ignore[method-assign]

        self.assertEqual(restarted.state.call_context("call_1")["calendar_event_id"], "evt_1")
        self.assertTrue(restarted.process_one_follow_up())
        self.assertEqual(len(calls), 1)
        with sqlite3.connect(self.state_db_path) as db:
            status = db.execute("SELECT status FROM follow_up_jobs").fetchone()[0]
        self.assertEqual(status, "done")

    def test_safe_logging_redacts_vapi_action_payload_fields(self):
        with tempfile.TemporaryDirectory() as tempdir:
            audit_path = os.path.join(tempdir, "audit.jsonl")
            os.environ["AUDIT_LOG_PATH"] = audit_path
            self.app.call_publicpa = lambda payload: "Available"  # type: ignore[method-assign]
            self.post_json(
                "/vapi/tools",
                {
                    "callId": "call_1",
                    "toolCalls": [
                        {
                            "id": "tool_secret",
                            "name": "check_availability",
                            "arguments": {"phone": PLACEHOLDER_SMS_FROM, "secret": "never-log"},
                        }
                    ],
                },
                headers={"x-vapi-secret": "vapi_secret"},
            )

            with open(audit_path, encoding="utf-8") as audit_file:
                serialized = audit_file.read()

        self.assertIn("vapi_action_processed", serialized)
        self.assertNotIn("never-log", serialized)
        self.assertNotIn(PLACEHOLDER_SMS_FROM, serialized)

    def test_main_rejects_invalid_port_without_starting_server(self):
        os.environ["PORT"] = "not-a-port"

        self.assertEqual(main(), 2)


if __name__ == "__main__":
    unittest.main()
