import contextlib
import base64
import email.parser
import hashlib
import hmac
import importlib
import io
import json
import os
import unittest
import urllib.parse
import urllib.error
from unittest import mock


AUTH_TOKEN = "test_auth_token"
ACCOUNT_SID = "ACtestaccount"
PUBLIC_HOST = "https://phone.dallasclounch.com"


class FakeSocket:
    def __init__(self, request_bytes):
        self._request = io.BytesIO(request_bytes)
        self.response = io.BytesIO()

    def makefile(self, mode, buffering=None):
        if "r" in mode:
            return self._request
        return self.response

    def sendall(self, data):
        self.response.write(data)

    def close(self):
        return


class ParsedResponse:
    def __init__(self, raw):
        head, _, self.body = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        self.status = int(lines[0].split()[1])
        self.headers = email.parser.Parser().parsestr("\n".join(lines[1:]))

    def getheader(self, name):
        return self.headers.get(name)


class FakeRelayResponse:
    def __init__(self, status=200, body=b"", content_type="text/xml"):
        self.status = status
        self._body = body
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


class BridgeTestCase(unittest.TestCase):
    def setUp(self):
        self.env_patch = mock.patch.dict(
            os.environ,
            {
                "TWILIO_AUTH_TOKEN": AUTH_TOKEN,
                "TWILIO_ACCOUNT_SID": ACCOUNT_SID,
                "PUBLIC_HOST": PUBLIC_HOST,
            },
            clear=False,
        )
        self.env_patch.start()
        import server

        self.server_mod = importlib.reload(server)
        self.stderr = io.StringIO()
        self.stderr_patch = mock.patch("sys.stderr", self.stderr)
        self.stderr_patch.start()

    def tearDown(self):
        self.stderr_patch.stop()
        self.env_patch.stop()

    @contextlib.contextmanager
    def relay_mock(self, status=200, body=None, content_type="text/xml; charset=utf-8", error=None):
        requests = []

        def fake_urlopen(req, timeout):
            requests.append(
                {
                    "url": req.full_url,
                    "body": req.data,
                    "signature": req.get_header("X-twilio-signature"),
                    "content_type": req.get_header("Content-type"),
                    "timeout": timeout,
                }
            )
            if error is not None:
                raise error
            return FakeRelayResponse(
                status=status,
                body=body
                if body is not None
                else b'<?xml version="1.0" encoding="UTF-8"?><Response><Message>ok</Message></Response>',
                content_type=content_type,
            )

        patcher = mock.patch("urllib.request.urlopen", side_effect=fake_urlopen)
        patcher.start()
        try:
            yield requests
        finally:
            patcher.stop()

    def request(self, method, path, body=b"", headers=None):
        headers = dict(headers or {})
        if body:
            headers["Content-Length"] = str(len(body))
        raw_headers = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        raw_request = f"{method} {path} HTTP/1.1\r\nHost: test.local\r\n{raw_headers}\r\n".encode("iso-8859-1") + body
        sock = FakeSocket(raw_request)
        self.server_mod.Handler(sock, ("127.0.0.1", 12345), object())
        response = ParsedResponse(sock.response.getvalue())
        return response, response.body

    def form_body(self, params):
        return urllib.parse.urlencode(params).encode("utf-8")

    def signature(self, path, params):
        signed = f"{PUBLIC_HOST}{path}" + "".join(f"{key}{params[key]}" for key in sorted(params))
        digest = hmac.new(AUTH_TOKEN.encode("utf-8"), signed.encode("utf-8"), hashlib.sha1).digest()
        return base64.b64encode(digest).decode("ascii")

    def assert_json_logs(self, *event_types):
        lines = [line for line in self.stderr.getvalue().splitlines() if line.strip().startswith("{")]
        events = [json.loads(line) for line in lines]
        for event_type in event_types:
            self.assertTrue(any(event.get("event") == event_type for event in events), events)
        return events


class HealthAndRootTests(BridgeTestCase):
    def test_get_and_head_root_and_health(self):
        for method, path in (("GET", "/"), ("HEAD", "/"), ("GET", "/health"), ("HEAD", "/health")):
            with self.subTest(method=method, path=path):
                response, data = self.request(method, path)
                self.assertEqual(response.status, 200)
                if method == "HEAD":
                    self.assertEqual(data, b"")

        response, data = self.request("GET", "/")
        self.assertIn(b"Voice remains on Vapi", data)

    def test_health_reports_configuration_booleans_without_values(self):
        with mock.patch.dict(os.environ, {"RELAY_URL": "", "RELAY_STATUS_URL": ""}, clear=False):
            response, data = self.request("GET", "/health")

        self.assertEqual(response.status, 200)
        payload = json.loads(data)
        self.assertIs(payload["twilio_auth_configured"], True)
        self.assertIs(payload["twilio_account_configured"], True)
        self.assertIs(payload["relay_configured"], False)
        self.assertIs(payload["relay_status_configured"], False)
        serialized = json.dumps(payload)
        self.assertNotIn(AUTH_TOKEN, serialized)
        self.assertNotIn(ACCOUNT_SID, serialized)


class SmsBridgeTests(BridgeTestCase):
    def test_twilio_sms_forwards_original_form_and_relay_twiml_response(self):
        params = {
            "AccountSid": ACCOUNT_SID,
            "MessageSid": "SM123",
            "From": "+148****0123",
            "To": "+148****7495",
            "Body": "hello Dara",
            "NumMedia": "0",
        }
        body = self.form_body(params)
        with self.relay_mock(status=201, content_type="application/xml") as relay_requests:
            relay_url = "https://public-pa.example/webhooks/twilio/sms"
            with mock.patch.dict(os.environ, {"RELAY_URL": relay_url}, clear=False):
                sig = self.signature("/twilio/sms", params)
                response, data = self.request(
                    "POST",
                    "/twilio/sms",
                    body,
                    {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Twilio-Signature": sig,
                    },
                )

        self.assertEqual(response.status, 201)
        self.assertEqual(response.getheader("Content-Type"), "application/xml")
        self.assertEqual(data, b'<?xml version="1.0" encoding="UTF-8"?><Response><Message>ok</Message></Response>')
        self.assertEqual(len(relay_requests), 1)
        self.assertEqual(relay_requests[0]["url"], relay_url)
        self.assertEqual(relay_requests[0]["body"], body)
        self.assertEqual(relay_requests[0]["signature"], sig)
        self.assertEqual(relay_requests[0]["content_type"], "application/x-www-form-urlencoded")
        self.assertLessEqual(relay_requests[0]["timeout"], 10)
        events = self.assert_json_logs("sms_accepted", "sms_relayed")
        self.assertNotIn("hello Dara", "\n".join(json.dumps(event) for event in events))

    def test_legacy_sms_path_still_validates_against_legacy_url(self):
        params = {"AccountSid": ACCOUNT_SID, "MessageSid": "SMlegacy", "From": "+148****0123", "To": "+148****7495"}
        body = self.form_body(params)
        with self.relay_mock() as relay_requests:
            with mock.patch.dict(os.environ, {"RELAY_URL": "https://public-pa.example/sms"}, clear=False):
                response, _ = self.request(
                    "POST",
                    "/sms",
                    body,
                    {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Twilio-Signature": self.signature("/sms", params),
                    },
                )
        self.assertEqual(response.status, 200)
        self.assertEqual(len(relay_requests), 1)

    def test_signature_must_match_exact_external_path(self):
        params = {"AccountSid": ACCOUNT_SID, "MessageSid": "SMbadpath", "From": "+148****0123", "To": "+148****7495"}
        response, data = self.request(
            "POST",
            "/twilio/sms",
            self.form_body(params),
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": self.signature("/sms", params),
            },
        )
        self.assertEqual(response.status, 403)
        self.assertIn(b"invalid_signature", data)

    def test_sms_relay_failure_returns_safe_502_and_logs_metadata(self):
        params = {"AccountSid": ACCOUNT_SID, "MessageSid": "SMfail", "From": "+148****0123", "To": "+148****7495"}
        body = self.form_body(params)
        error = urllib.error.HTTPError("https://public-pa.example/sms", 503, "unavailable", {}, io.BytesIO(b"secret downstream body"))
        with self.relay_mock(error=error):
            with mock.patch.dict(os.environ, {"RELAY_URL": "https://public-pa.example/sms"}, clear=False):
                response, data = self.request(
                    "POST",
                    "/twilio/sms",
                    body,
                    {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Twilio-Signature": self.signature("/twilio/sms", params),
                    },
                )
        self.assertEqual(response.status, 502)
        self.assertEqual(data, b'{"error":"relay_failed"}')
        log_text = self.stderr.getvalue()
        self.assertIn('"event": "relay_failed"', log_text)
        self.assertNotIn("secret downstream body", log_text)


class StatusCallbackTests(BridgeTestCase):
    def test_status_callback_logs_audit_forwards_when_configured_and_returns_204(self):
        params = {
            "AccountSid": ACCOUNT_SID,
            "MessageSid": "SMstatus",
            "SmsStatus": "delivered",
            "ErrorCode": "",
            "From": "+148****0123",
            "To": "+148****7495",
        }
        body = self.form_body(params)
        with self.relay_mock(status=204, body=b"") as relay_requests:
            relay_url = "https://public-pa.example/status"
            with mock.patch.dict(os.environ, {"RELAY_STATUS_URL": relay_url}, clear=False):
                response, data = self.request(
                    "POST",
                    "/twilio/status",
                    body,
                    {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-Twilio-Signature": self.signature("/twilio/status", params),
                    },
                )

        self.assertEqual(response.status, 204)
        self.assertEqual(data, b"")
        self.assertEqual(relay_requests[0]["body"], body)
        events = self.assert_json_logs("status_callback", "status_relayed")
        callback = next(event for event in events if event["event"] == "status_callback")
        self.assertEqual(callback["message_sid"], "SMstatus")
        self.assertEqual(callback["status"], "delivered")
        self.assertEqual(callback["error_code"], "")
        self.assertEqual(callback["from"], "***0123")
        self.assertEqual(callback["to"], "***7495")

    def test_status_invalid_signature_returns_403(self):
        params = {"MessageSid": "SMstatus", "SmsStatus": "failed"}
        response, _ = self.request(
            "POST",
            "/twilio/status",
            self.form_body(params),
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": self.signature("/twilio/sms", params),
            },
        )
        self.assertEqual(response.status, 403)
