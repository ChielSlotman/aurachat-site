# AuraChat Website

This is a simple static site for **AuraChat**, matching the dark neon style of the extension.

The site includes:

- **index.html** – Landing page with hero, features and calls to action.
- **pricing.html** – Pricing cards and placeholder for a Stripe Pricing Table. Edit `config.js` with your Stripe publishable key and Pricing Table ID to embed your table.
- **success.html** – After checkout, this page reads a `session_id` query parameter, calls your backend exchange endpoint, and displays the one‑time activation code for your extension. It also offers a copy button.
- **faq.html** – Answers to common questions.
- **support.html** – Contact information and instructions for restoring Premium.
- **404.html** – Basic not found page.
- **config.js** – Central place to set your backend base URL, checkout exchange path, Stripe keys and support email.
- **styles.css** – Dark theme with neon gradients, matching your extension UI.
- **img/** – Contains your logo and banner images.

## Set up

1. **Edit `config.js`**
   Fill in your backend URL, exchange path, Stripe publishable key, Stripe Pricing Table ID and support email.

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
