# Transactional Email and DMARC Checklist

Provider: Brevo (Sendinblue)

Templates

1) Activation code delivered
- Subject: Your AuraSync activation code
- Body: Includes code block, short instructions, support link, and legal footer.

2) Lost code
- Subject: Your new AuraSync activation code
- Body: Explain previous tokens revoked, include new code, support link, and legal footer.

3) Purchase receipt notice
- Subject: Thanks for your AuraSync purchase
- Body: Confirmation with support link and legal footer (Stripe sends the official receipt separately).

Implementation notes
- From: FROM_EMAIL (no-reply@aurasync.info recommended)
- All emails include company name, link to https://aurasync.info/support/, and legal links https://aurasync.info/legal/
- Avoid full emails in logs; masking is implemented in the backend.

DNS and deliverability
- SPF: Add TXT at aurasync.info: v=spf1 include:spf.brevo.com ~all
- DKIM: Create the CNAME records provided by Brevo for domain signing.
- DMARC: Add TXT _dmarc.aurasync.info: v=DMARC1; p=quarantine; rua=mailto:dmarc@aurasync.info; ruf=mailto:dmarc@aurasync.info; fo=1; adkim=s; aspf=s
- Monitor bounces/complaints in Brevo dashboard.

Testing
- Send to Gmail and Outlook test inboxes; check spam placement.
- Verify headers contain Authentication-Results with spf=pass dkim=pass dmarc=pass.
