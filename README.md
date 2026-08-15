# dara-phone-bridge

Secure Twilio SMS webhook bridge for Dara Public PA.

Public hostname: `phone.dallasclounch.com`

This service accepts inbound SMS from Twilio, verifies the Twilio request signature, and forwards the message to Public PA. It does not handle voice. Voice on `+1 (480) 771-7495` stays on Vapi.

## Endpoints

- `GET /health` health check
- `POST /sms` Twilio inbound SMS webhook
- `GET /` short status page

## Required environment

- `TWILIO_AUTH_TOKEN`
- `TWILIO_ACCOUNT_SID`
- `PUBLIC_PA_URL` Public PA base URL that can receive forwarded SMS
- `PUBLIC_HOST` public webhook base, default `https://phone.dallasclounch.com`
- `PORT` provided by the host, default `8080`

## Twilio

Set only the SMS webhook for `+1 (480) 771-7495` to:

`https://phone.dallasclounch.com/sms`

Leave the voice webhook on Vapi.
