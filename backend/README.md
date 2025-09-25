# AuraSync Backend

## Render Setup


### Stripe Price IDs

Configure one or more price IDs so the webhook can map purchases to plans:

- STRIPE_PRICE_MONTHLY=price_...
- STRIPE_PRICE_YEARLY=price_...
- STRIPE_PRICE_LIFETIME=price_...
- STRIPE_ALLOWED_PRICE_IDS=price_abc,price_def

If none are set, the server will warn on boot and ignore unrecognized prices.

## Admin lost-code testing (support-only)

For QA/support, use the admin-only route that simulates the recovery flow without daily limits:

- Route: `POST /admin/test-lost-code`
- Headers: `Authorization: Bearer <ADMIN_SECRET>` (or `X-Admin-Secret: <ADMIN_SECRET>`) and `Content-Type: application/json`
- Body: `{ "email": "user@example.com", "token": "<existing token or license code>" }`

PowerShell example:

```
curl -Method POST -Uri "$env:API_BASE/admin/test-lost-code" -Headers @{ 'Content-Type'='application/json'; 'Authorization'="Bearer $env:ADMIN_SECRET" } -Body '{"email":"user@example.com","token":"wi_..."}'
```

There is also a simple admin page at `/admin/` to trigger this flow; it requires the admin secret.

## Minimal Lost Code endpoint (public)

Add-on/extension uses a minimal endpoint to resend the license code when a user has an active subscription.

- Route: `POST /lost-code`
- Headers: `Content-Type: application/json`
- Body: `{ "email": "user@example.com" }`
- Success: `200 { "success": true }`
- Failures:
	- `400 { "success": false, "error": "invalid_input" }` (bad or missing email)
	- `400 { "success": false, "error": "no_subscription" }` (not active or trialing)
	- `429 { "success": false, "error": "rate_limited" }` (optional 1 email/day, in-memory)
	- `500 { "success": false, "error": "send_failed" }` (provider/email error)

Behavior:
1) Normalize email (trim + lowercase).
2) Check subscription using the same helper as purchase (active OR trialing on Stripe).
3) Get the same license code used on purchase (reuse generator/format when needed).
4) Send the same email template as purchase.
5) Return `{ success: true }`.

Headers:
- CORS: uses the existing allowlist, including the extension origin.
- Cache: `Cache-Control: no-store`.
