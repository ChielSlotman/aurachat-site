# AuraSync Website

This is a simple static site for **AuraSync**, matching the dark neon style of the extension.

The site includes:

- **index.html** – Landing page with hero, features and calls to action.
- **pricing.html** – Pricing cards and placeholder for a Stripe Pricing Table. Edit `config.js` with your Stripe publishable key and Pricing Table ID to embed your table.
- **success.html** – After checkout, this page reads a `session_id` query parameter, calls your backend exchange endpoint, and displays the one‑time activation code for your extension. It also offers a copy button.
- **faq.html** – Answers to common questions.
- **support.html** – Contact information and instructions for restoring Premium.
- **404.html** – Basic not found page.
- **config.js** – Central place to set your backend base URL, checkout exchange path, Stripe keys and support email.
- **styles.css** – Dark theme with neon gradients, matching your extension UI.
- **logo/** – Contains your logo and banner images.

## Set up

1. **Edit `config.js`**
   Fill in your backend URL, exchange path, Stripe publishable key, Stripe Pricing Table ID and support email.
   - To enable the Manage Billing button on `pricing.html`, either set `PORTAL_URL` to your Stripe Customer Portal shareable link, or provide `BACKEND_BASE` and `PORTAL_SESSION_PATH` for a server endpoint that creates a portal session and returns `{ url }`.

2. **Deploy to GitHub Pages**
   - Create a new repository and upload these files.
   - In GitHub settings → Pages, select the `main` branch and `/` folder as the source.
   - Optionally add a custom domain and create a CNAME record with your DNS provider.

3. **Configure Stripe Checkout**
   - In Stripe, create a Pricing Table and copy its ID and your publishable key into `config.js`.
   - Set your checkout success URL to `https://YOUR-DOMAIN/success.html?session_id={{CHECKOUT_SESSION_ID}}`.

4. **Activate Premium**
   - After checkout, the user will land on `success.html`, copy the activation code, open the AuraChat extension, and paste the code.

Enjoy!

## Backend (server)

There is an optional Node/Express backend in `backend/` that handles code issuance and Stripe webhooks.

Endpoints:

- POST /create-checkout-session
- POST /activate
- POST /redeem
- GET /status
- POST /lost-code
- GET /debug/stripe
- POST /stripe/webhook (signature-verified, idempotent)
- GET /healthz (ok/version/uptime/now)
- POST /billing-portal (Stripe customer portal)

In production, required envs are enforced: STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET.

## Windows Admin Launcher

To run the local admin UI on Windows without a console window:

- Double-click `run-admin-py.bat`.
- It launches a small Python GUI (`run-admin.pyw`) that starts the backend, waits for health, and opens the Admin page with the admin secret prefilled.

Requirements:
- Python 3.x installed and available on PATH (it will try `pythonw.exe`, then `python.exe`, then `py.exe`).
- Node.js and npm installed (the first run will install backend dependencies automatically).

## SEO

Static files `robots.txt` and `sitemap.xml` are included at the web root.
