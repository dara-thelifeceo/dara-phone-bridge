import contextlib
import base64
import email.parser
import hashlib
import hmac
import importlib
import io
import json
import os
import socket
import unittest
import urllib.parse
import urllib.error
from unittest import mock


AUTH_TOKEN = "test_auth_token"
ACCOUNT_SID = "ACtestaccount"
PUBLIC_HOST = "https://phone.dallasclounch.com"
VAPI_SECRET = "test_vapi_secret"
VAPI_RELAY_URL = "https://public-pa.example/vapi/events"
VAPI_TOOLS_URL = "https://public-pa.example/vapi/tools"
VAPI_ACTIONS_URL = "https://public-pa.example/vapi/actions"


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
                    "vapi_secret": req.get_header("X-vapi-secret"),
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

    @contextlib.contextmanager
    def relay_sequence(self, outcomes):
        requests = []
        remaining = list(outcomes)

        def fake_urlopen(req, timeout):
            requests.append(
                {
                    "url": req.full_url,
                    "body": req.data,
                    "vapi_secret": req.get_header("X-vapi-secret"),
                    "content_type": req.get_header("Content-type"),
                    "timeout": timeout,
                }
            )
            outcome = remaining.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return FakeRelayResponse(
                status=outcome.get("status", 200),
                body=outcome.get("body", b""),
                content_type=outcome.get("content_type", "application/json"),
            )

        patcher = mock.patch("urllib.request.urlopen", side_effect=fake_urlopen)
        patcher.start()
        try:
            yield requests
        finally:
            patcher.stop()

    def request(self, method, path, body=b"", headers=None):
        headers = dict(headers or {})
        if body and "Content-Length" not in headers:
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
            with mock.patch.dict(os.environ, {"VAPI_WEBHOOK_SECRET": "", "VAPI_RELAY_URL": ""}, clear=False):
                response, data = self.request("GET", "/health")

        self.assertEqual(response.status, 200)
        payload = json.loads(data)
        self.assertIs(payload["twilio_auth_configured"], True)
        self.assertIs(payload["twilio_account_configured"], True)
        self.assertIs(payload["relay_configured"], False)
        self.assertIs(payload["relay_status_configured"], False)
        self.assertIs(payload["vapi_webhook_secret_configured"], True)
        self.assertIs(payload["vapi_relay_configured"], False)
        self.assertIs(payload["vapi_events_relay_configured"], False)
        self.assertIs(payload["vapi_tools_relay_configured"], False)
        self.assertIs(payload["vapi_actions_relay_configured"], False)
        serialized = json.dumps(payload)
        self.assertNotIn(AUTH_TOKEN, serialized)
        self.assertNotIn(ACCOUNT_SID, serialized)

    def test_health_reports_effective_vapi_fallback_configuration(self):
        with mock.patch.dict(
            os.environ,
            {
                "VAPI_WEBHOOK_SECRET": "",
                "VAPI_RELAY_URL": "",
                "RELAY_URL": "https://public-pa.example/twilio/sms",
            },
            clear=False,
        ):
            response, data = self.request("GET", "/health")

        self.assertEqual(response.status, 200)
        payload = json.loads(data)
        self.assertIs(payload["vapi_webhook_secret_configured"], True)
        self.assertIs(payload["vapi_relay_configured"], True)
        self.assertIs(payload["vapi_events_relay_configured"], True)
        self.assertIs(payload["vapi_tools_relay_configured"], True)
        self.assertIs(payload["vapi_actions_relay_configured"], True)
        serialized = json.dumps(payload)
        self.assertNotIn(AUTH_TOKEN, serialized)
        self.assertNotIn("public-pa.example", serialized)


class SmsBridgeTests(BridgeTestCase):
    def test_twilio_sms_forwards_original_form_and_relay_twiml_response(self):
        params = {
            "AccountSid": ACCOUNT_SID,
            "MessageSid": "SM123",
            "From": "+14805550123",
            "To": "+14807717495",
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
        self.assertEqual(relay_requests[0]["timeout"], 8)
        events = self.assert_json_logs("sms_accepted", "sms_relayed")
        self.assertNotIn("hello Dara", "\n".join(json.dumps(event) for event in events))

    def test_legacy_sms_path_still_validates_against_legacy_url(self):
        params = {"AccountSid": ACCOUNT_SID, "MessageSid": "SMlegacy", "From": "+14805550123", "To": "+14807717495"}
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
        params = {"AccountSid": ACCOUNT_SID, "MessageSid": "SMbadpath", "From": "+14805550123", "To": "+14807717495"}
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
        params = {"AccountSid": ACCOUNT_SID, "MessageSid": "SMfail", "From": "+14805550123", "To": "+14807717495"}
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
            "From": "+14805550123",
            "To": "+14807717495",
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


class VapiEventTests(BridgeTestCase):
    def vapi_body(self):
        return json.dumps(
            {
                "type": "transcript",
                "phoneNumber": "+14805550123",
                "message": {"content": "sensitive transcript"},
                "recordingUrl": "https://recordings.example/private.wav",
            }
        ).encode("utf-8")

    def vapi_env(self):
        return mock.patch.dict(
            os.environ,
            {"VAPI_WEBHOOK_SECRET": VAPI_SECRET, "VAPI_RELAY_URL": VAPI_RELAY_URL},
            clear=False,
        )

    def test_vapi_missing_effective_secret_returns_503_without_relay(self):
        with self.vapi_env(), self.relay_mock() as relay_requests:
            with mock.patch.dict(os.environ, {"VAPI_WEBHOOK_SECRET": "", "TWILIO_AUTH_TOKEN": ""}, clear=False):
                response, data = self.request(
                    "POST",
                    "/vapi/events",
                    b'{"type":"event"}',
                    {"Content-Type": "application/json"},
                )

        self.assertEqual(response.status, 503)
        self.assertEqual(data, b'{"error":"vapi_not_configured"}')
        self.assertEqual(relay_requests, [])

    def test_vapi_missing_header_returns_403_without_relay(self):
        with self.vapi_env(), self.relay_mock() as relay_requests:
            response, data = self.request(
                "POST",
                "/vapi/events",
                b'{"type":"event"}',
                {"Content-Type": "application/json"},
            )

        self.assertEqual(response.status, 403)
        self.assertEqual(data, b'{"error":"forbidden"}')
        self.assertEqual(relay_requests, [])

    def test_vapi_invalid_secret_returns_403_without_relay(self):
        with self.vapi_env(), self.relay_mock() as relay_requests:
            response, _ = self.request(
                "POST",
                "/vapi/events",
                b'{"type":"event"}',
                {"Content-Type": "application/json", "x-vapi-secret": "wrong"},
            )

        self.assertEqual(response.status, 403)
        self.assertEqual(relay_requests, [])

    def test_vapi_valid_x_vapi_secret_relays_exact_json_and_returns_204(self):
        body = self.vapi_body()
        with self.vapi_env(), self.relay_mock(status=202, body=b"accepted", content_type="application/json") as relay_requests:
            response, data = self.request(
                "POST",
                "/vapi/events",
                body,
                {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
            )

        self.assertEqual(response.status, 204)
        self.assertEqual(data, b"")
        self.assertEqual(len(relay_requests), 1)
        self.assertEqual(relay_requests[0]["url"], VAPI_RELAY_URL)
        self.assertEqual(relay_requests[0]["body"], body)
        self.assertEqual(relay_requests[0]["content_type"], "application/json")
        self.assertEqual(relay_requests[0]["vapi_secret"], VAPI_SECRET)
        self.assertEqual(relay_requests[0]["timeout"], 8)

    def test_vapi_tools_returns_exact_host_json_status_body_content_type(self):
        body = json.dumps(
            {
                "call": {"id": "call_123"},
                "toolCalls": [{"id": "tool_1"}, {"id": "tool_2"}],
                "input": {"secret_text": "do not log"},
            }
        ).encode("utf-8")
        host_body = b'{"results":[{"toolCallId":"tool_1","result":"ok"}]}'
        with self.vapi_env(), self.relay_mock(status=201, body=host_body, content_type="application/json; charset=utf-8") as relay_requests:
            response, data = self.request(
                "POST",
                "/vapi/tools",
                body,
                {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
            )

        self.assertEqual(response.status, 201)
        self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
        self.assertEqual(data, host_body)
        self.assertEqual(len(relay_requests), 1)
        self.assertEqual(relay_requests[0]["url"], VAPI_TOOLS_URL)
        self.assertEqual(relay_requests[0]["body"], body)
        self.assertEqual(relay_requests[0]["vapi_secret"], VAPI_SECRET)
        self.assertEqual(relay_requests[0]["timeout"], 58)
        events = self.assert_json_logs("vapi_relay_started", "vapi_relayed")
        started = next(event for event in events if event["event"] == "vapi_relay_started")
        self.assertEqual(started["endpoint"], "/vapi/tools")
        self.assertEqual(started["call_id"], "call_123")
        self.assertEqual(started["tool_call_ids"], ["tool_1", "tool_2"])
        log_text = self.stderr.getvalue()
        self.assertNotIn("do not log", log_text)
        self.assertNotIn(VAPI_SECRET, log_text)

    def test_vapi_actions_derives_matching_host_url_from_sms_relay_url(self):
        body = b'{"callId":"call_action","toolCall":{"id":"tool_action"}}'
        host_body = b'{"ok":true}'
        with self.relay_mock(status=200, body=host_body, content_type="application/json") as relay_requests:
            with mock.patch.dict(
                os.environ,
                {
                    "VAPI_WEBHOOK_SECRET": "",
                    "VAPI_RELAY_URL": "",
                    "RELAY_URL": "https://public-pa.example/webhooks/twilio/sms",
                },
                clear=False,
            ):
                response, data = self.request(
                    "POST",
                    "/vapi/actions",
                    body,
                    {"Content-Type": "application/json", "Authorization": f"Bearer {AUTH_TOKEN}"},
                )

        self.assertEqual(response.status, 200)
        self.assertEqual(data, host_body)
        self.assertEqual(len(relay_requests), 1)
        self.assertEqual(relay_requests[0]["url"], "https://public-pa.example/webhooks/vapi/actions")
        self.assertEqual(relay_requests[0]["vapi_secret"], AUTH_TOKEN)
        self.assertEqual(relay_requests[0]["timeout"], 58)

    def test_vapi_sync_relay_timeout_is_configurable(self):
        body = b'{"call":{"id":"call_timeout_config"},"toolCalls":[{"id":"tool_timeout_config"}]}'
        with self.vapi_env(), self.relay_mock(status=200, body=b'{"ok":true}', content_type="application/json") as relay_requests:
            with mock.patch.dict(os.environ, {"VAPI_RELAY_TIMEOUT_SECONDS": "42"}, clear=False):
                response, data = self.request(
                    "POST",
                    "/vapi/tools",
                    body,
                    {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
                )

        self.assertEqual(response.status, 200)
        self.assertEqual(data, b'{"ok":true}')
        self.assertEqual(len(relay_requests), 1)
        self.assertEqual(relay_requests[0]["timeout"], 42.0)

    def test_vapi_sync_host_http_error_status_and_json_body_are_passthrough(self):
        body = b'{"call":{"id":"call_bad"},"toolCalls":[{"id":"tool_bad"}]}'
        headers = {"Content-Type": "application/json"}
        error = urllib.error.HTTPError(VAPI_TOOLS_URL, 422, "unprocessable", headers, io.BytesIO(b'{"error":"bad_tool"}'))
        with self.vapi_env(), self.relay_mock(error=error):
            response, data = self.request(
                "POST",
                "/vapi/tools",
                body,
                {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
            )

        self.assertEqual(response.status, 422)
        self.assertEqual(response.getheader("Content-Type"), "application/json")
        self.assertEqual(data, b'{"error":"bad_tool"}')

    def test_vapi_events_tool_calls_preserves_non_empty_host_json_response(self):
        body = b'{"message":{"type":"tool-calls","call":{"id":"call_evt"},"toolCalls":[{"id":"tool_evt"}]}}'
        host_body = b'{"toolCallId":"tool_evt","result":"ok"}'
        with self.vapi_env(), self.relay_mock(status=200, body=host_body, content_type="application/json") as relay_requests:
            response, data = self.request(
                "POST",
                "/vapi/events",
                body,
                {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
            )

        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "application/json")
        self.assertEqual(data, host_body)
        self.assertEqual(relay_requests[0]["url"], VAPI_RELAY_URL)
        self.assertEqual(relay_requests[0]["timeout"], 58)

    def test_vapi_events_normal_async_still_returns_204_when_host_has_body(self):
        body = b'{"type":"transcript","call":{"id":"call_async"}}'
        with self.vapi_env(), self.relay_mock(status=200, body=b'{"accepted":true}', content_type="application/json"):
            response, data = self.request(
                "POST",
                "/vapi/events",
                body,
                {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
            )

        self.assertEqual(response.status, 204)
        self.assertEqual(data, b"")

    def test_vapi_host_relay_retries_transient_errors_then_succeeds(self):
        body = b'{"call":{"id":"call_retry"},"toolCalls":[{"id":"tool_retry"}]}'
        with self.vapi_env(), self.relay_sequence(
            [
                urllib.error.URLError("temporary outage"),
                {"status": 200, "body": b'{"ok":true}', "content_type": "application/json"},
            ]
        ) as relay_requests:
            with mock.patch("time.sleep") as sleep_mock:
                response, data = self.request(
                    "POST",
                    "/vapi/tools",
                    body,
                    {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
                )

        self.assertEqual(response.status, 200)
        self.assertEqual(data, b'{"ok":true}')
        self.assertEqual(len(relay_requests), 2)
        sleep_mock.assert_called_once_with(0.2)
        events = self.assert_json_logs("vapi_relay_retry", "vapi_relayed")
        retry = next(event for event in events if event["event"] == "vapi_relay_retry")
        self.assertEqual(retry["call_id"], "call_retry")
        self.assertEqual(retry["tool_call_ids"], ["tool_retry"])

    def test_vapi_sync_relay_timeout_is_not_retried(self):
        body = b'{"call":{"id":"call_timeout"},"toolCalls":[{"id":"tool_timeout"}]}'
        timeout_error = urllib.error.URLError(socket.timeout("timed out"))
        with self.vapi_env(), self.relay_sequence([timeout_error]) as relay_requests:
            with mock.patch("time.sleep") as sleep_mock:
                response, data = self.request(
                    "POST",
                    "/vapi/tools",
                    body,
                    {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
                )

        self.assertEqual(response.status, 502)
        self.assertEqual(data, b'{"error":"relay_failed"}')
        self.assertEqual(len(relay_requests), 1)
        self.assertEqual(relay_requests[0]["timeout"], 58)
        sleep_mock.assert_not_called()
        events = self.assert_json_logs("vapi_relay_failed")
        self.assertFalse(any(event.get("event") == "vapi_relay_retry" for event in events))

    def test_vapi_valid_bearer_secret_relays(self):
        with self.vapi_env(), self.relay_mock(status=204) as relay_requests:
            response, _ = self.request(
                "POST",
                "/vapi/events",
                b'{"type":"event"}',
                {"Content-Type": "application/json", "Authorization": f"Bearer {VAPI_SECRET}"},
            )

        self.assertEqual(response.status, 204)
        self.assertEqual(len(relay_requests), 1)

    def test_vapi_falls_back_to_twilio_token_and_derived_relay_url(self):
        body = self.vapi_body()
        with self.relay_mock(status=204) as relay_requests:
            with mock.patch.dict(
                os.environ,
                {
                    "VAPI_WEBHOOK_SECRET": "",
                    "VAPI_RELAY_URL": "",
                    "RELAY_URL": "https://public-pa.example/sms",
                },
                clear=False,
            ):
                response, data = self.request(
                    "POST",
                    "/vapi/events",
                    body,
                    {"Content-Type": "application/json", "x-vapi-secret": AUTH_TOKEN},
                )

        self.assertEqual(response.status, 204)
        self.assertEqual(data, b"")
        self.assertEqual(len(relay_requests), 1)
        self.assertEqual(relay_requests[0]["url"], "https://public-pa.example/vapi/events")
        self.assertEqual(relay_requests[0]["body"], body)
        self.assertEqual(relay_requests[0]["vapi_secret"], AUTH_TOKEN)
        self.assertNotIn(AUTH_TOKEN, self.stderr.getvalue())

    def test_vapi_derives_relay_url_from_twilio_sms_suffix(self):
        with self.relay_mock(status=204) as relay_requests:
            with mock.patch.dict(
                os.environ,
                {
                    "VAPI_WEBHOOK_SECRET": "",
                    "VAPI_RELAY_URL": "",
                    "RELAY_URL": "https://public-pa.example/webhooks/twilio/sms",
                },
                clear=False,
            ):
                response, _ = self.request(
                    "POST",
                    "/vapi/events",
                    b'{"type":"event"}',
                    {"Content-Type": "application/json", "Authorization": f"Bearer {AUTH_TOKEN}"},
                )

        self.assertEqual(response.status, 204)
        self.assertEqual(len(relay_requests), 1)
        self.assertEqual(relay_requests[0]["url"], "https://public-pa.example/webhooks/vapi/events")

    def test_vapi_malformed_json_returns_400_without_relay(self):
        with self.vapi_env(), self.relay_mock() as relay_requests:
            response, data = self.request(
                "POST",
                "/vapi/events",
                b'{"type":',
                {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
            )

        self.assertEqual(response.status, 400)
        self.assertEqual(data, b'{"error":"invalid_json"}')
        self.assertEqual(relay_requests, [])

    def test_vapi_oversized_json_returns_413_without_relay(self):
        body = b'{"type":"event"}'
        with self.vapi_env(), self.relay_mock() as relay_requests:
            response, data = self.request(
                "POST",
                "/vapi/events",
                body,
                {
                    "Content-Type": "application/json",
                    "x-vapi-secret": VAPI_SECRET,
                    "Content-Length": str((2 * 1024 * 1024) + 1),
                },
            )

        self.assertEqual(response.status, 413)
        self.assertEqual(data, b'{"error":"body_too_large"}')
        self.assertEqual(relay_requests, [])

    def test_vapi_relay_failure_returns_safe_502_and_redacts_logs(self):
        body = self.vapi_body()
        error = urllib.error.HTTPError(VAPI_RELAY_URL, 503, "unavailable", {}, io.BytesIO(b"sensitive relay body"))
        with self.vapi_env(), self.relay_mock(error=error):
            response, data = self.request(
                "POST",
                "/vapi/events",
                body,
                {"Content-Type": "application/json", "x-vapi-secret": VAPI_SECRET},
            )

        self.assertEqual(response.status, 502)
        self.assertEqual(data, b'{"error":"relay_failed"}')
        log_text = self.stderr.getvalue()
        self.assertIn('"event": "vapi_relay_failed"', log_text)
        for sensitive in (
            "sensitive transcript",
            "+14805550123",
            "recordings.example",
            VAPI_SECRET,
            "sensitive relay body",
            "Authorization",
            "x-vapi-secret",
        ):
            self.assertNotIn(sensitive, log_text)
