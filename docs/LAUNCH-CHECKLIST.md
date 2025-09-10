# Launch Checklist

- [ ] Stripe success URL has ?session_id={CHECKOUT_SESSION_ID}
- [ ] Webhook set to /stripe/webhook with live secret configured
- [ ] CORS only allows prod origins
- [ ] Healthz green and shows version
- [ ] Robots and sitemap live
- [ ] Terms, Privacy, Refunds, Cookies, Support linked in footer
- [ ] One live purchase tested end to end
- [ ] Email templates render and deliver
- [ ] Logs contain masked emails only
- [ ] CI green and test keys blocked
- [ ] Extension listing privacy matches site privacy
