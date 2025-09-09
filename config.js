// AuraChat Website Config
// Update these values to match your backend and Stripe configuration
window.AURASYNC_CONFIG = {
  // Base URL of your backend (no trailing slash)
  BACKEND_BASE: "https://YOUR-BACKEND.onrender.com",
  // Path to exchange a Checkout Session for an activation code
  EXCHANGE_PATH: "/exchange-session",
  // Link to your Stripe customer portal (optional)
  PORTAL_URL: "https://billing.stripe.com/p/YOUR-CUSTOMER-PORTAL-LINK",
  // Optional: Backend path that creates a Stripe Billing Portal session and returns { url }
  // Example implementation: POST BACKEND_BASE + PORTAL_SESSION_PATH -> { url: "https://billing.stripe.com/session/..." }
  PORTAL_SESSION_PATH: "/create-portal-session",
  // Stripe publishable key (required for the pricing table)
  STRIPE_PUBLISHABLE_KEY: "pk_test_replace_me",
  // ID of your Stripe Pricing Table
  STRIPE_PRICING_TABLE_ID: "prctbl_replace_me",
  // Email address users should contact for support
  CONTACT_EMAIL: "support@example.com"
};
// Back-compat for pages still reading AURACHAT_CONFIG
window.AURACHAT_CONFIG = window.AURASYNC_CONFIG;
