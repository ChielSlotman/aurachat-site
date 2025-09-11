# AuraSync Backend

## Render Setup

- Set env vars: DATABASE_URL, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET.
- For SSL: either upload CA to the repo at backend/certs/db-ca.pem and set PG_CA_PATH, or paste the CA into PG_CA_BUNDLE. If the DB uses a self-signed chain and you are blocked, temporarily set PG_SSL_INSECURE=true to confirm connectivity, then replace with a proper CA.
- Set the Render Start Command to npm start and the Root Directory to backend if the service is multi-root.
- Health check path /health.

### Stripe Price IDs

Configure one or more price IDs so the webhook can map purchases to plans:

- STRIPE_PRICE_MONTHLY=price_...
- STRIPE_PRICE_YEARLY=price_...
- STRIPE_PRICE_LIFETIME=price_...
- STRIPE_ALLOWED_PRICE_IDS=price_abc,price_def

If none are set, the server will warn on boot and ignore unrecognized prices.
