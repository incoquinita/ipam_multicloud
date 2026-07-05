# TLS Certificates

This directory holds the TLS certificate and key used by nginx for TLS
termination. Real certificates are git-ignored (`*.pem`) and must be
generated locally or provisioned by your deployment pipeline.

## Self-signed certificate (local development)

Generate a self-signed cert valid for one year:

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

This produces two files in the current directory:

- `cert.pem` — public certificate (sent to clients)
- `key.pem` — private key (keep secret, never commit)

## Production

For production deployments, replace these with certificates issued by a
trusted Certificate Authority (e.g. Let's Encrypt, or your internal CA).
Mount the CA-issued `cert.pem` and `key.pem` into this directory, or
adjust the `ssl_certificate` / `ssl_certificate_key` paths in
`nginx/nginx.conf` to point at your provisioning location.

## Security note

Both files are excluded from version control via `.gitignore`
(`nginx/certs/*.pem`). Never commit real private keys.
