# userver-web-push

A userver component for sending browser push notifications via the Web Push
protocol (RFC 8030) with VAPID authentication (RFC 8292) and payload
encryption (RFC 8291). Designed to be plugged into any userver-based project
as a library.

## Overview

The library provides:

- **`webpush::Client`** — a userver component that handles VAPID
  authentication, payload encryption, and push delivery.
- **`webpush::Credentials`** — VAPID key pair + contact URI, loadable from
  config or constructed programmatically for multi-tenant setups.
- **`webpush::handlers::DebugSend`** — an optional HTTP handler for sending
  test pushes using the component's default credentials.
- **`crypto::ecdh`**, **`crypto::hkdf`**, **`crypto::aes_gcm`** — userver-style
  crypto primitives (ECDH P-256, HKDF-SHA256, AES-128-GCM) implemented
  against OpenSSL 3.0, designed for future upstreaming to userver.

For VAPID key generation and deployment configuration see [SETUP.md](SETUP.md).

## Web Push Protocol

### How It Works

Unlike APNs/FCM where there's a single push service, Web Push works with
any push service. Each browser subscription includes an endpoint URL that
points to the browser vendor's push service (Google, Mozilla, Microsoft,
etc.). The server encrypts the payload and POSTs it to that endpoint.

### API

```
POST {subscription.endpoint}
```

**Required headers:**

| Header | Description |
|---|---|
| `Authorization` | `vapid t=<jwt>,k=<public_key_base64url>` |
| `Content-Encoding` | `aes128gcm` |
| `Content-Type` | `application/octet-stream` |
| `TTL` | Time-to-live in seconds (mandatory per RFC 8030) |

**Request body:** Encrypted payload in aes128gcm format (binary).

**Payload limit:** ~4096 bytes (encrypted).

**Response codes:**

| Status | Meaning |
|---|---|
| 201 | Created — push accepted |
| 400 | Invalid request |
| 401 | VAPID authentication failed |
| 404 | Subscription not found |
| 410 | Subscription expired — remove from database |
| 413 | Payload too large |
| 429 | Rate limited — retry with backoff |
| 500/503 | Push service error — retry with backoff |

### Authentication (VAPID, RFC 8292)

VAPID uses an **EC P-256 key pair** and **ES256 JWT** — the same signing
algorithm as Apple APNs.

The JWT claims:
- `aud` — origin of the push service (derived from the subscription endpoint)
- `sub` — contact URI (e.g. `mailto:admin@example.com`)
- `exp` — expiration (max 24 hours from now)

The `Authorization` header format:
```
vapid t=<jwt>,k=<base64url_uncompressed_public_key>
```

Since the `aud` varies per push service and JWT signing is purely local
(no HTTP exchange), VAPID tokens are generated per-call. There is no
token caching or background refresh.

### Payload Encryption (RFC 8291)

Every Web Push payload must be encrypted with the subscriber's keys. The
encryption uses:

1. **ECDH key agreement** — ephemeral P-256 key pair + subscriber's `p256dh`
2. **HKDF-SHA256** — derives content encryption key and nonce
3. **AES-128-GCM** — encrypts the padded payload

The encrypted body format (aes128gcm):
```
salt(16) || record_size(4, big-endian) || keyid_len(1) || server_pubkey(65) || ciphertext+tag
```

A fresh ephemeral key pair and random salt are generated for every message.

### Subscription

A browser push subscription contains three values:

```json
{
    "endpoint": "https://fcm.googleapis.com/fcm/send/...",
    "keys": {
        "p256dh": "base64url-encoded-public-key",
        "auth": "base64url-encoded-auth-secret"
    }
}
```

These come from the browser's `PushSubscription` object after calling
`pushManager.subscribe()`.

## Component Design

### `webpush::Credentials`

```cpp
namespace webpush {

struct Credentials {
    std::string private_key_pem;  // EC P-256 private key for VAPID signing
    std::string public_key;       // base64url uncompressed P-256 public key
    std::string subject;          // contact URI, e.g. "mailto:admin@example.com"

    static auto FromConfig(const ComponentConfig&) -> Credentials;
};

}  // namespace webpush
```

### `webpush::Client`

```cpp
namespace webpush {

struct Subscription {
    std::string endpoint;
    std::string p256dh;     // base64url
    std::string auth;       // base64url
};

struct Notification {
    Subscription subscription;
    std::string payload;    // plaintext JSON to encrypt and send
    std::int32_t ttl = 3600;
};

struct SendResult {
    std::int32_t status_code;   // 201 = success, 400-503 = error, 0 = transport/crypto error
    std::string reason;
};

class Client final : public userver::components::ComponentBase {
public:
    static constexpr std::string_view kName = "webpush-client";

    /// Send using the component's default VAPID credentials.
    [[nodiscard]] auto Send(const Notification& notification) const -> SendResult;

    /// Send using explicit credentials (for multi-tenant setups).
    [[nodiscard]] auto Send(
        const Credentials& credentials,
        const Notification& notification
    ) const -> SendResult;
};

}  // namespace webpush
```

### `webpush::handlers::DebugSend`

An optional handler for testing. Uses default credentials — no credentials
accepted via HTTP.

**Request** — `POST` with JSON body:

```json
{
    "subscription": {
        "endpoint": "https://fcm.googleapis.com/fcm/send/...",
        "keys": {
            "p256dh": "...",
            "auth": "..."
        }
    },
    "payload": {
        "title": "Test",
        "body": "Hello from debug handler"
    },
    "ttl": 3600
}
```

**Response:**

```json
{
    "status_code": 201,
    "reason": ""
}
```

**Static config:**

```yaml
webpush-handler-debug-send:
    path: /webpush/debug/send
    method: POST
    task_processor: main-task-processor
    webpush-client: webpush-client
```

### Configuration

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

### Service Integration

**CMakeLists.txt:**

```cmake
add_subdirectory(third-party/userver-web-push/webpush)
target_link_libraries(your-service PRIVATE webpush_client)
```

**main.cpp:**

```cpp
#include <webpush/components/client.hpp>
#include <webpush/handlers/debug_send.hpp>

auto component_list = userver::components::MinimalServerComponentList()
    .Append<userver::components::HttpClient>()
    .Append<userver::clients::dns::Component>()
    .Append<webpush::Client>()
    .Append<webpush::handlers::DebugSend>()    // optional
    ;
```

**Sending:**

```cpp
auto& client = context.FindComponent<webpush::Client>();

webpush::Notification notification;
notification.subscription = {
    .endpoint = "https://fcm.googleapis.com/fcm/send/...",
    .p256dh = "base64url-public-key",
    .auth = "base64url-auth-secret",
};
notification.payload = R"({"title":"Hi","body":"Hello"})";

auto result = client.Send(notification);
// result.status_code == 201 on success
```

## Crypto Primitives

The library includes three userver-style crypto modules that wrap OpenSSL 3.0.
They follow userver conventions (RAII, `CryptoException`, `USERVER_NAMESPACE`)
and are designed for future upstreaming.

### `userver/crypto/ecdh.hpp`

EC P-256 ephemeral key generation and ECDH shared secret derivation.

### `userver/crypto/hkdf.hpp`

HKDF-SHA256 key derivation (RFC 5869).

### `userver/crypto/aes_gcm.hpp`

AES-128-GCM authenticated encryption.

## Library Structure

```
webpush/
├── CMakeLists.txt
├── include/
│   ├── userver/crypto/          # userver-style crypto (future upstream PR)
│   │   ├── ecdh.hpp
│   │   ├── hkdf.hpp
│   │   └── aes_gcm.hpp
│   └── webpush/
│       ├── components/
│       │   └── client.hpp
│       ├── handlers/
│       │   └── debug_send.hpp
│       └── types/
│           ├── credentials.hpp
│           ├── subscription.hpp
│           ├── notification.hpp
│           └── result.hpp
├── src/
│   ├── crypto/
│   │   ├── helpers.hpp
│   │   ├── helpers.cpp
│   │   ├── ecdh.cpp
│   │   ├── hkdf.cpp
│   │   └── aes_gcm.cpp
│   └── webpush/
│       ├── components/
│       │   └── client.cpp
│       ├── handlers/
│       │   └── debug_send.cpp
│       ├── vapid/
│       │   ├── token.hpp
│       │   └── token.cpp
│       └── encrypt/
│           ├── payload.hpp
│           └── payload.cpp
└── tests/
    ├── ecdh_test.cpp
    ├── hkdf_test.cpp
    ├── aes_gcm_test.cpp
    ├── encrypt_test.cpp
    ├── vapid_test.cpp
    └── notification_test.cpp
```

## Dependencies

- **userver** (core, universal) — HTTP client, ES256 signing, base64url, JSON,
  logging
- **OpenSSL 3.0+** — ECDH, HKDF, AES-GCM (via EVP API)

## License

Apache License 2.0
