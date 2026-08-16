# dara-phone-bridge

Production Twilio SMS edge bridge for Dara Public PA.

Public hostname: `phone.dallasclounch.com`

This Railway service accepts Twilio SMS webhooks, verifies the Twilio request
signature against `PUBLIC_HOST` plus the exact externally requested path, and
relays the original `application/x-www-form-urlencoded` body to the existing
host-side Public PA bridge endpoint. It does not create resources and does not
handle voice. Voice routing stays on Vapi.

## Endpoints

- `GET /` and `HEAD /` status page
- `GET /health` and `HEAD /health` health check
- `POST /twilio/sms` canonical Twilio inbound SMS webhook
- `POST /sms` legacy inbound SMS webhook
- `POST /twilio/status` Twilio SMS status callback

## Environment

- `TWILIO_AUTH_TOKEN` Twilio auth token used only for signature validation
- `TWILIO_ACCOUNT_SID` Twilio account SID; reported as configured/not configured
- `PUBLIC_HOST` public webhook base, default `https://phone.dallasclounch.com`
- `RELAY_URL` existing OS-managed Public PA bridge endpoint for inbound SMS
- `RELAY_STATUS_URL` optional existing OS-managed Public PA bridge endpoint for SMS status callbacks
- `PORT` provided by Railway, default `8080`

`/health` reports booleans for Twilio and relay configuration. It never returns
secret values and does not claim Public PA relay configuration when relay
variables are absent.

## Twilio URLs

Set SMS for `+1 (480) 771-7495` to:

`https://phone.dallasclounch.com/twilio/sms`

Set SMS status callback to:

`https://phone.dallasclounch.com/twilio/status`

Leave voice on Vapi:

- Voice webhook: `https://api.vapi.ai/twilio/inbound_call`
- Voice status callback: `https://api.vapi.ai/twilio/status`

## Behavior

- Invalid Twilio signatures return `403`.
- Successful SMS requests return the relay response status, TwiML body, and content type.
- SMS relay failures return a safe `502` so Twilio can retry.
- Successful status callbacks return `204`.
- Logs are structured JSON and avoid request bodies, secrets, and full phone numbers.

## Test

```sh
python -m unittest discover -v
```
