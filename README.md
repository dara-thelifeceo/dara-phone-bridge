# Dara Phone Bridge

Minimal Python stdlib HTTP webhook bridge for Dallas's Dara Public PA phone stack.

## What It Does

- `POST /twilio/sms`: validates `X-Twilio-Signature`, immediately returns empty TwiML, then asks the local Public PA OpenAI-compatible endpoint for one outbound SMS reply and sends it back through Twilio.
- `POST /twilio/voice`: validates `X-Twilio-Signature` and returns TwiML that forwards the call to `VOICE_FORWARD_TO` with caller ID `VOICE_CALLER_ID`.
- `POST /twilio/status`: validates `X-Twilio-Signature`, persists delivery status metadata, and logs status metadata only.
- `POST /vapi/events`: validates `x-vapi-secret` or `Authorization: Bearer ...`, deduplicates Vapi events by call ID and event type, immediately returns `204`, then asynchronously forwards safe end-of-call report fields to Public PA.
- `POST /vapi/tools` and `POST /vapi/actions`: validate `x-vapi-secret` or `Authorization: Bearer ...`, parse Vapi tool-call envelope variants, synchronously delegate calendar actions to Public PA, and return Vapi-compatible tool results.
- `GET /` and `HEAD /`: return a minimal service status.
- `GET /health`: returns JSON booleans for required settings and never returns secret values.

The bridge prevents open relay behavior: only validated inbound Twilio webhooks trigger replies, replies always go to the request `From`, and Twilio sends from the request `To`.

Inbound SMS `MessageSid` values are stored in SQLite for idempotency. If Twilio retries the same inbound message, the bridge returns the same empty TwiML response without queueing another Public PA call or outbound reply. Vapi action IDs are also stored durably; duplicate action delivery returns the original stored tool result without calling Public PA again. The SQLite state keeps the most recent 12 inbound/outbound SMS turns per peer, prunes SMS turns older than 30 days, stores call context, stores scheduled follow-up jobs, and records correlations between inbound message SID, Vapi call/action IDs, Twilio provider SID/status, and Google Calendar event ID when Public PA returns one.

Message bodies are stored only in the local SQLite conversation state. They are never written to stdout, journald, or audit JSONL records. Vapi transcripts and recording URLs are not persisted or forwarded.

## Configuration

Environment variables:

```sh
PUBLIC_BASE_URL=https://phone.dallasclounch.com
PUBLICPA_ENDPOINT=https://your-isolated-public-pa.example/v1/chat/completions
VOICE_FORWARD_TO=+155****0102
VOICE_CALLER_ID=+155****0103
HOST=0.0.0.0
PORT=8080
LOG_LEVEL=INFO
AUDIT_LOG_PATH=/var/lib/dara-phone-bridge/audit.jsonl
STATE_DB_PATH=/var/lib/dara-phone-bridge/state.sqlite3
PUBLICPA_TIMEOUT_SECONDS=60
VAPI_PUBLICPA_ACTION_BUDGET_SECONDS=82
VAPI_WEBHOOK_SECRET=change-me
```

Defaults:

- `PUBLICPA_ENDPOINT`: `http://127.0.0.1:8644/v1/chat/completions`
- `PUBLICPA_ENV_PATH`: `/home/dara-public/.hermes/profiles/publicpa/.env`
- `TWILIO_ENV_PATH`: `/root/.hermes/.env`
- `HOST`: `0.0.0.0`
- `PORT`: `8080`
- `AUDIT_LOG_PATH`: unset
- `STATE_DB_PATH`: `/var/lib/dara-phone-bridge/state.sqlite3`
- `PUBLICPA_TIMEOUT_SECONDS`: `60`
- `VAPI_PUBLICPA_ACTION_BUDGET_SECONDS`: `82`, capped at `88`

Required secrets:

- `API_SERVER_KEY` in `PUBLICPA_ENV_PATH`, or in the process environment.
- `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` in `TWILIO_ENV_PATH`, or in the process environment.
- `VAPI_WEBHOOK_SECRET` if `POST /vapi/events` is enabled in Vapi. If it is unset, the already configured `TWILIO_AUTH_TOKEN` is used as the effective Vapi webhook secret for compatibility.

Required voice routing:

- `VOICE_FORWARD_TO`: destination phone number in E.164 format, for example `+15555550102`.
- `VOICE_CALLER_ID`: verified Twilio caller ID in E.164 format, for example `+15555550103`.

If either voice routing value is missing, `POST /twilio/voice` returns HTTP 503 with safe TwiML instead of returning a malformed `<Dial>`.

`PUBLIC_BASE_URL` must exactly match the public URL Twilio uses before the webhook path. For this deployment it is `https://phone.dallasclounch.com`.

When `AUDIT_LOG_PATH` is set, structured events are appended as JSON Lines to that file. Audit records omit message bodies and secrets and mask full phone numbers. The bridge creates the configured file's parent directory if needed, uses a thread lock for writes, and logs audit write failures without failing Twilio webhook handling.

`STATE_DB_PATH` stores inbound SMS idempotency, bounded SMS conversation history, Twilio status metadata, and Vapi event dedupe state. The bridge creates the parent directory if needed and sets the SQLite file mode to `0600`.

Public PA calls use `PUBLICPA_TIMEOUT_SECONDS`. Vapi synchronous calendar actions use `VAPI_PUBLICPA_ACTION_BUDGET_SECONDS` as the total Public PA retry lifetime; each HTTP attempt is capped to the remaining budget so the bridge can return before Vapi's 90 second tool timeout. Outbound SMS replies are truncated to 1500 characters before submission to Twilio.

Public PA and Twilio outbound calls use bounded exponential retries for transient failures (`408`, `409`, `429`, `5xx`, URL/network timeout errors). Calendar availability and booking logic is never performed by this bridge; the bridge prompts the configured OpenAI-compatible Public PA endpoint to use Google Calendar and return concise speech-safe responses.

## Run

```sh
python3 dara_phone_bridge.py
```

With explicit settings:

```sh
PUBLIC_BASE_URL=https://phone.dallasclounch.com VOICE_FORWARD_TO=+155****0102 VOICE_CALLER_ID=+155****0103 HOST=0.0.0.0 PORT=8080 python3 dara_phone_bridge.py
```

## Test

```sh
python3 -m unittest discover -s tests
```

Tests use only stdlib modules and do not make network calls to Twilio or Public PA.

## Railway deployment

The checked-in `Dockerfile`, `.dockerignore`, and `railway.json` make this repository directly deployable as a **new Railway service**. Do not attach it to or modify Railway Pulse or the existing `dallasclounch-com` service.

Set these variables on the new service (secret values belong only in Railway, never in Git):

- `PUBLIC_BASE_URL=https://phone.dallasclounch.com`
- `PUBLICPA_ENDPOINT`: HTTPS OpenAI-compatible endpoint for the isolated Public PA service
- `API_SERVER_KEY`: bearer key for that isolated endpoint
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `VOICE_FORWARD_TO` and `VOICE_CALLER_ID` only if voice forwarding is enabled
- `STATE_DB_PATH=/var/lib/dara-phone-bridge/state.sqlite3`
- `PUBLICPA_TIMEOUT_SECONDS=60`
- `VAPI_PUBLICPA_ACTION_BUDGET_SECONDS=82`
- `VAPI_WEBHOOK_SECRET` if Vapi server events are configured. When absent, `TWILIO_AUTH_TOKEN` is the effective Vapi webhook secret.

Railway supplies `PORT`; the service listens on `0.0.0.0`. The configured health check is `/health`. After the first successful deployment, add `phone.dallasclounch.com` as the new service's custom domain and create the DNS record Railway displays. Do not point DNS at another service.

`PUBLICPA_ENV_PATH` and `TWILIO_ENV_PATH` are host-service compatibility options. On Railway, inject the corresponding secret variables directly instead of relying on files.

## Twilio Webhooks

Configure Twilio to send:

- Incoming SMS webhook: `POST https://phone.dallasclounch.com/twilio/sms`
- Incoming voice webhook: `POST https://phone.dallasclounch.com/twilio/voice`
- Message or call status callback: `POST https://phone.dallasclounch.com/twilio/status`

## Vapi Webhook

Configure Vapi server events to send:

- Server events webhook: `POST https://phone.dallasclounch.com/vapi/events`
- Tool/action endpoint: `POST https://phone.dallasclounch.com/vapi/tools` (or `/vapi/actions`)
- Authentication: either `x-vapi-secret: $VAPI_WEBHOOK_SECRET` or `Authorization: Bearer $VAPI_WEBHOOK_SECRET`. If `VAPI_WEBHOOK_SECRET` is unset, use the configured `TWILIO_AUTH_TOKEN` value instead.

The endpoint accepts only valid JSON up to 256 KiB. It deduplicates by call ID plus event type and processes only `end-of-call-report` asynchronously. Public PA receives only safe structured fields: call ID/type/status/endedReason, summary, structuredData, customer phone, and assistantOverrides when present.

### Vapi Tool Contract

The synchronous action endpoint accepts common Vapi envelopes including:

- Top-level `toolCalls`, `toolCallList`, `toolCall`, `functionCall`, or `action`
- Nested `message.toolCalls`, `message.toolCallList`, `message.functionCall`, or `message.action`
- Tool IDs from `id`, `toolCallId`, `tool_call_id`, or nested action/function IDs
- Tool names from `name`, `toolName`, `tool_name`, or nested `function.name` / `action.name`
- Arguments as JSON objects or JSON strings from `arguments`, `parameters`, or `input`

Supported tool names and aliases:

- `check_availability`, `checkAvailability`, `availability`
- `create_booking`, `createBooking`, `book`
- `reschedule_booking`, `rescheduleBooking`, `reschedule`
- `cancel_booking`, `cancelBooking`, `cancel`
- `read_back`, `readBack`, `readback`

Response:

```json
{
  "results": [
    {
      "toolCallId": "tool-call-id-from-vapi",
      "result": "Concise speech-safe sentence for the caller.",
      "success": true,
      "calendar_event_id": "optional-google-calendar-event-id"
    }
  ]
}
```

Duplicate `toolCallId` values return the stored JSON result. Unknown tools return a Vapi-compatible failed result and are persisted for idempotency.

## systemd Example

Create `/etc/systemd/system/dara-phone-bridge.service`:

```ini
[Unit]
Description=Dara Phone Bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dara-public
Group=dara-public
WorkingDirectory=/opt/dara-phone-bridge
Environment=PUBLIC_BASE_URL=https://phone.example.com
Environment=VOICE_FORWARD_TO=+15555550102
Environment=VOICE_CALLER_ID=+15555550103
Environment=HOST=127.0.0.1
Environment=PORT=8080
Environment=AUDIT_LOG_PATH=/var/lib/dara-phone-bridge/audit.jsonl
Environment=STATE_DB_PATH=/var/lib/dara-phone-bridge/state.sqlite3
Environment=PUBLICPA_TIMEOUT_SECONDS=60
ExecStart=/usr/bin/python3 /opt/dara-phone-bridge/dara_phone_bridge.py
Restart=always
RestartSec=3
StateDirectory=dara-phone-bridge
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now dara-phone-bridge
sudo journalctl -u dara-phone-bridge -f
```

## nginx Example

```nginx
server {
    listen 443 ssl http2;
    server_name phone.example.com;

    ssl_certificate /etc/letsencrypt/live/phone.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phone.example.com/privkey.pem;

    location /twilio/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 30s;
    }

    location /vapi/events {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 30s;
    }

    location /health {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Keep `PUBLIC_BASE_URL` aligned with the externally visible nginx URL.
