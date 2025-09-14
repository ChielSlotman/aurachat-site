# AuraSync Backend

## Render Setup


### Stripe Price IDs

Configure one or more price IDs so the webhook can map purchases to plans:

- STRIPE_PRICE_MONTHLY=price_...
- STRIPE_PRICE_YEARLY=price_...
- STRIPE_PRICE_LIFETIME=price_...
- STRIPE_ALLOWED_PRICE_IDS=price_abc,price_def

If none are set, the server will warn on boot and ignore unrecognized prices.

## Lost-code testing: bypass 7-day limit

For QA and support you can bypass the 7-day cooldown on the `/lost-code` endpoint.

Two ways to enable:

1) Send `Authorization: Bearer <ADMIN_SECRET>` header and include `{ force: true }` in the JSON body.
	- The admin secret is configured via `ADMIN_SECRET` env.
2) Set env `ALLOW_FORCE_LOST_CODE=true` (intended for local/dev) and include `{ force: true }` in the body.

Request body shape now supports an optional `force` field:

```
{ "email": "user@example.com", "token": "wi_... or CODE", "force": true }
```

PowerShell examples:

```
# Using Authorization: Bearer ADMIN_SECRET
curl -Method POST -Uri "$env:API_BASE/lost-code" -Headers @{ 'Content-Type'='application/json'; 'Authorization'="Bearer $env:ADMIN_SECRET" } -Body '{"email":"user@example.com","token":"wi_...","force":true}'

# Using ALLOW_FORCE_LOST_CODE=true (no auth header)
curl -Method POST -Uri "$env:API_BASE/lost-code" -Headers @{ 'Content-Type'='application/json' } -Body '{"email":"user@example.com","token":"wi_...","force":true}'
```

There is also a simple admin page at `/admin/` that posts to `/lost-code` with `force:true`. It requires pasting the admin secret in the form to send the Authorization header.
