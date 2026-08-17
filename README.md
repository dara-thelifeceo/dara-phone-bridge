# dara-phone-bridge

Production Twilio SMS and Vapi relay edge bridge for Dara Public PA.

Public hostname: `phone.dallasclounch.com`

This existing Railway service accepts Twilio SMS webhooks, verifies the Twilio request
signature against `PUBLIC_HOST` plus the exact externally requested path, and
relays the original `application/x-www-form-urlencoded` body to the existing
host-side Public PA bridge endpoint. It also accepts authenticated Vapi server
events, tool calls, and actions, then relays the exact JSON body to the
matching existing host-side Vapi endpoint. It does not create a new service,
does not create credentials, and does not handle voice call routing. Voice
routing stays on Vapi.

## Endpoints

- `GET /` and `HEAD /` status page
- `GET /health` and `HEAD /health` health check
- `POST /twilio/sms` canonical Twilio inbound SMS webhook
- `POST /sms` legacy inbound SMS webhook
- `POST /twilio/status` Twilio SMS status callback
- `POST /vapi/events` authenticated Vapi server event relay
- `POST /vapi/tools` authenticated synchronous Vapi tool relay
- `POST /vapi/actions` authenticated synchronous Vapi action relay

## Environment

- `TWILIO_AUTH_TOKEN` Twilio auth token used for Twilio signature validation;
  also used as a compatibility fallback Vapi webhook secret when
  `VAPI_WEBHOOK_SECRET` is absent
- `TWILIO_ACCOUNT_SID` Twilio account SID; reported as configured/not configured
- `PUBLIC_HOST` public webhook base, default `https://phone.dallasclounch.com`
- `RELAY_URL` existing OS-managed Public PA bridge endpoint for inbound SMS
- `RELAY_STATUS_URL` optional existing OS-managed Public PA bridge endpoint for SMS status callbacks
- `VAPI_WEBHOOK_SECRET` shared Vapi event webhook secret
- `VAPI_RELAY_URL` existing OS-managed Public PA bridge endpoint for Vapi events,
  tools, or actions
- `PORT` provided by Railway, default `8080`

`/health` reports booleans for Twilio, SMS relay, and Vapi events/tools/actions
relay configuration. It never returns secret or URL values and does not claim
Public PA relay configuration when relay variables are absent.

Compatibility fallback: if `VAPI_WEBHOOK_SECRET` is absent, Vapi auth uses
`TWILIO_AUTH_TOKEN` as the shared secret. If `VAPI_RELAY_URL` is absent, the
Vapi relay URL is derived from `RELAY_URL` by replacing a trailing `/twilio/sms`
or `/sms` path with the requested Vapi path, such as `/vapi/events`,
`/vapi/tools`, or `/vapi/actions`. If `VAPI_RELAY_URL` is set to one Vapi path,
the existing service derives the matching sibling Vapi path for the current
request. The dedicated `VAPI_WEBHOOK_SECRET` and `VAPI_RELAY_URL` variables
remain preferred and should be set when Railway variable management is
available.

## Twilio URLs

Set SMS for `+1 (480) 771-7495` to:

`https://phone.dallasclounch.com/twilio/sms`

Set SMS status callback to:

`https://phone.dallasclounch.com/twilio/status`

Leave voice on Vapi:

- Voice webhook: `https://api.vapi.ai/twilio/inbound_call`
- Voice status callback: `https://api.vapi.ai/twilio/status`

## Vapi URL

Set the Vapi server event webhook to:

`https://phone.dallasclounch.com/vapi/events`

Set Vapi tool and action endpoints to the existing Railway service as needed:

- `https://phone.dallasclounch.com/vapi/tools`
- `https://phone.dallasclounch.com/vapi/actions`

Send the shared secret as either `x-vapi-secret` or `Authorization: Bearer ...`.

## Behavior

- Invalid Twilio signatures return `403`.
- Successful SMS requests return the relay response status, TwiML body, and content type.
- SMS relay failures return a safe `502` so Twilio can retry.
- Successful status callbacks return `204`.
- Vapi event, tool, and action requests use the same shared secret, require
  valid JSON, and are capped at 2 MiB.
- Normal accepted async Vapi events return `204` after the host relay accepts
  the event.
- Vapi `/vapi/events` tool-calls envelopes preserve a non-empty host JSON
  response instead of forcing `204`.
- Vapi `/vapi/tools` and `/vapi/actions` relay synchronously and return the
  exact host JSON status, body, and content type to Vapi.
- Vapi host relay uses bounded transient retries with exponential backoff.
- Vapi auth, validation, and relay failures return safe `4xx` or `5xx` JSON errors.
- Logs are structured JSON and avoid request bodies, headers, secrets, message
  content, transcripts, phone numbers, and recording URLs. Vapi relay logs
  include redacted correlation fields for call ID and tool call IDs only.

## Test

```sh
python -m unittest discover -v
python -m py_compile server.py tests/test_server.py
```
