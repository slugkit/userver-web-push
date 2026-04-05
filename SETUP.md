# Web Push Setup Guide

Complete guide to generating VAPID keys, configuring browser subscriptions,
and deploying to production.

## 1. Generate VAPID Key Pair

VAPID uses an EC P-256 key pair. Generate one with OpenSSL:

```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out vapid_private.pem

# Convert to PKCS#8 format (required)
openssl pkcs8 -topk8 -nocrypt -in vapid_private.pem -out vapid_private_pkcs8.pem

# Extract uncompressed public key (65 bytes, base64url encoded)
openssl ec -in vapid_private_pkcs8.pem -pubout -conv_form uncompressed -outform DER 2>/dev/null \
    | tail -c 65 \
    | basenc --base64url -w0 \
    | tr -d '='
```

Or as a single command that outputs all three values:

```bash
openssl ecparam -genkey -name prime256v1 -noout 2>/dev/null \
    | openssl pkcs8 -topk8 -nocrypt 2>/dev/null > vapid_private_pkcs8.pem

echo "VAPID_PRIVATE_KEY_PEM:"
cat vapid_private_pkcs8.pem

echo ""
echo "VAPID_PUBLIC_KEY:"
openssl ec -in vapid_private_pkcs8.pem -pubout -conv_form uncompressed -outform DER 2>/dev/null \
    | tail -c 65 \
    | basenc --base64url -w0 \
    | tr -d '='
echo ""
```

You should get:
- **Private key PEM** — starts with `-----BEGIN PRIVATE KEY-----`
- **Public key** — 86-character base64url string (65 bytes uncompressed P-256
  point: `0x04` + 32-byte x + 32-byte y)

**Keep the private key secret.** The public key is shared with browsers.

## 2. Summary of Credentials

| Value | Example | Env Var |
|---|---|---|
| Private key PEM | `-----BEGIN PRIVATE KEY-----\nMIGH...` | `VAPID_PRIVATE_KEY_PEM` |
| Public key (base64url) | `BDkN3...` (86 chars) | `VAPID_PUBLIC_KEY` |
| Contact URI | `mailto:admin@example.com` | `VAPID_SUBJECT` |

The **subject** is a contact URI (mailto: or https:) that push services can
use to contact you if there's a problem. It's included in the VAPID JWT.

## 3. Browser-Side Setup

The browser needs the VAPID public key to create a subscription. The public
key must be provided as a `Uint8Array` to `pushManager.subscribe()`.

### Service Worker Registration

```javascript
// Register service worker
const registration = await navigator.serviceWorker.register('/sw.js');

// Convert base64url public key to Uint8Array
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    return Uint8Array.from([...rawData].map(c => c.charCodeAt(0)));
}

// Subscribe to push
const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array('YOUR_VAPID_PUBLIC_KEY_HERE')
});

// Send subscription to your server
await fetch('/api/subscribe', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(subscription)
});
```

### Service Worker (sw.js)

```javascript
self.addEventListener('push', event => {
    const data = event.data.json();
    event.waitUntil(
        self.registration.showNotification(data.title, {
            body: data.body,
            icon: data.icon
        })
    );
});
```

### Subscription Object

The `subscription` object from the browser looks like:

```json
{
    "endpoint": "https://fcm.googleapis.com/fcm/send/...",
    "expirationTime": null,
    "keys": {
        "p256dh": "BNcR...base64url...",
        "auth": "tBHI...base64url..."
    }
}
```

Store the `endpoint`, `keys.p256dh`, and `keys.auth` on your server for
each subscribed device.

## 4. Environment Variables

All credentials are passed via environment variables. **Never bake
credentials into Docker images or config files checked into git.**

### Required

| Variable | Description |
|---|---|
| `VAPID_PRIVATE_KEY_PEM` | Full PEM content of the EC P-256 private key (PKCS#8 format) |
| `VAPID_PUBLIC_KEY` | Base64url-encoded uncompressed P-256 public key (86 characters) |
| `VAPID_SUBJECT` | Contact URI (`mailto:admin@example.com` or `https://example.com`) |

### Setting from the generated files

```bash
export VAPID_PRIVATE_KEY_PEM="$(cat vapid_private_pkcs8.pem)"
export VAPID_PUBLIC_KEY="$(openssl ec -in vapid_private_pkcs8.pem -pubout \
    -conv_form uncompressed -outform DER 2>/dev/null | tail -c 65 \
    | basenc --base64url -w0 | tr -d '=')"
export VAPID_SUBJECT="mailto:admin@example.com"
```

## 5. Service Configuration

Add to your service's `static_config.yaml`:

```yaml
webpush-client:
    private-key-pem: ""
    private-key-pem#env: VAPID_PRIVATE_KEY_PEM
    public-key: ""
    public-key#env: VAPID_PUBLIC_KEY
    subject: ""
    subject#env: VAPID_SUBJECT
    request-timeout: 10s
```

## 6. Local Development

Create a `.env` file (already gitignored):

```bash
VAPID_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----"
VAPID_PUBLIC_KEY="BDkN3..."
VAPID_SUBJECT="mailto:dev@localhost"
```

## 7. Production Deployment

### fly.io

```bash
fly secrets set VAPID_PRIVATE_KEY_PEM="$(cat vapid_private_pkcs8.pem)"
fly secrets set VAPID_PUBLIC_KEY="BDkN3..."
fly secrets set VAPID_SUBJECT="mailto:admin@example.com"
```

### Kubernetes

```bash
kubectl create secret generic vapid-credentials \
    --from-file=VAPID_PRIVATE_KEY_PEM=vapid_private_pkcs8.pem \
    --from-literal=VAPID_PUBLIC_KEY="BDkN3..." \
    --from-literal=VAPID_SUBJECT="mailto:admin@example.com"
```

```yaml
containers:
  - name: api
    envFrom:
      - secretRef:
          name: vapid-credentials
```

## 8. Key Rotation

VAPID keys don't expire, but you may want to rotate them:

1. Generate a new key pair.
2. Update the public key in your frontend JavaScript.
3. Deploy the new frontend.
4. Update `VAPID_PRIVATE_KEY_PEM` and `VAPID_PUBLIC_KEY` in secrets.
5. Deploy the backend.

**Important:** Existing browser subscriptions were created with the old
public key. After key rotation, those subscriptions will reject pushes
with `401 Unauthorized`. Users must re-subscribe with the new key. Plan
key rotation carefully.

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| HTTP 401 | VAPID signature invalid | Verify private key matches public key |
| HTTP 410 | Subscription expired or revoked | Remove from database, user must re-subscribe |
| HTTP 413 | Payload too large | Keep plaintext under ~3.8 KB (encryption adds overhead) |
| HTTP 429 | Rate limited | Implement exponential backoff |
| `status_code = 0`, crypto error | Encryption failed | Verify subscription `p256dh` and `auth` are valid base64url |
| `status_code = 0`, network error | Can't reach push service | Check connectivity to the subscription endpoint host |
| Startup crash: `private-key-pem is not configured` | Missing env var | Check secrets config |
| Startup crash: `invalid private-key-pem` | Not PKCS#8 EC P-256 PEM | Verify key starts with `-----BEGIN PRIVATE KEY-----`, re-generate with PKCS#8 |
| Browser: `InvalidAccessError` on subscribe | Wrong public key format | Must be uncompressed P-256 (65 bytes), base64url, no padding |
