-- A private ACME authority (step-ca, a home PKI) in place of Let's Encrypt: its
-- directory, and the root PEM that both Caddy — talking to it — and the controller —
-- verifying the certificates it issued — must trust. Public certificates, no secret.
ALTER TABLE exposure ADD COLUMN acme_ca TEXT;
ALTER TABLE exposure ADD COLUMN acme_ca_root TEXT;
