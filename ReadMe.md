# MockPass OIDC Authenticator for WSO2 Identity Server

A custom WSO2 Identity Server authenticator implementing a **FAPI-compliant OIDC flow** for MockPass (Singpass v3).

It extends WSO2's built-in `OpenIDConnectAuthenticator` and adds the security layers required by Singpass — PAR, PKCE, DPoP, private-key JWT client authentication, and JWE ID token decryption.

---

## Project Layout

```
authenticator/
├── src/
│   └── main/java/com/example/wso2/
│       └── internal/
│           ├── CustomAuthenticatorServiceComponent.java
│           ├── JWTUtil.java
│           └── MockPassOIDCAuthenticator.java   ← custom authenticator
├── mockpass-relay/
│   └──  index.js                                 ← relay server
├── generate-jwks.js                             ← JWKS generation script
├── jwks.json                                    ← exported public JWKS
└── pom.xml
```

---

## Security Features

| Feature | Description |
|---|---|
| **PAR** | Pushed Authorization Requests — auth params sent via backchannel before browser redirect |
| **PKCE** | Proof Key for Code Exchange (S256) — prevents authorization code interception |
| **DPoP** | Demonstrating Proof of Possession — binds tokens to the client using an ephemeral EC key |
| **Private-key JWT** | Client authentication using a signed JWT instead of a shared secret |
| **JWE** | Encrypted ID token (ECDH-ES) — decrypted with a local EC private key |

---

## Prerequisites

- JDK 11+
- Apache Maven 3.8+
- Node.js (for relay server and JWKS generation)
- WSO2 Identity Server 7.2.0
- MockPass running locally on port 5156
- `openssl` — for EC key and certificate generation

---

## Authentication Flow

```
1. User clicks "Login with Singpass"
        │
        ▼
2. WSO2 calls initiateAuthenticationRequest()
        │
        generates: state, nonce, PKCE, ephemeral key, DPoP, client assertion
        │
        POST ──► MockPass /par   (backchannel — user never sees this)
        ◄── { request_uri, expires_in }
        │
        Browser redirect ──► MockPass /auth
                             ?client_id=mock
                             &request_uri=urn:...
        │
        ▼
3. User logs in on MockPass login page
        │
        ▼
4. MockPass redirects to Relay
        /callback?code=abc123&state=uuid.sessionDataKey
        │
        Relay splits state ──► WSO2 /commonauth
                               ?code=abc123
                               &state=uuid
                               &sessionDataKey=xxx
        │
        ▼
5. WSO2 calls processAuthenticationResponse()
        │
        validates state (CSRF check) ✓
        │
        POST ──► MockPass /token   (backchannel)
                 code + code_verifier + client_assertion + DPoP
        ◄── { access_token, id_token (encrypted JWE) }
        │
        decrypts JWE id_token using enc.p12
        extracts claims (NRIC etc.)
        builds AuthenticatedUser
        │
        ▼
6. WSO2 issues its own tokens to your app
        User is logged in ✓
```

---

## Step 1: Generate EC Keys & Keystores

Two keystores are required — one for **signing** (client assertion JWT) and one for **encryption** (JWE ID token decryption).

### Signing Key (`carbon.p12`)

Used to sign the `client_assertion` JWT sent to MockPass at both the PAR and token endpoints.

```bash
# Generate EC private key
openssl ecparam -name prime256v1 -genkey -noout -out ec-private.key

# Generate self-signed certificate
openssl req -new -x509 -key ec-private.key \
  -out ec-cert.pem \
  -days 365 \
  -subj "/CN=MockPass Client/OU=Dev/O=Example/L=Singapore/C=SG"

# Package into PKCS12 keystore
openssl pkcs12 -export \
  -inkey ec-private.key \
  -in ec-cert.pem \
  -out carbon.p12 \
  -name mockpass-key \
  -passout pass:<your-password>
```

### Encryption Key (`enc.p12`)

Used to decrypt the JWE-wrapped ID token returned by MockPass. MockPass encrypts the ID token using your registered public key — only your private key can decrypt it.

```bash
# Generate EC private key
openssl ecparam -name prime256v1 -genkey -noout -out enc-key.pem

# Generate self-signed certificate
openssl req -new -x509 -key enc-key.pem \
  -out enc-cert.pem \
  -days 365 \
  -subj "/CN=MockPass Encryption/OU=Dev/O=Example/L=Singapore/C=SG"

# Package into PKCS12 keystore
openssl pkcs12 -export \
  -inkey enc-key.pem \
  -in enc-cert.pem \
  -out enc.p12 \
  -name mockpass-enc-key \
  -passout pass:<your-password>
```

These commands generate EC key pairs, create self-signed certificates, and package them into `.p12` keystores for WSO2.

---

## Step 2: Generate JWKS

The `jwks.json` file contains your public keys and is provided to MockPass so it can verify your client assertion signatures and encrypt ID tokens to you.

```bash
node generate-jwks.js
```

This produces `jwks.json` with two entries:

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "mockpass-key",
      "x": "...",
      "y": "..."
    },
    {
      "kty": "EC",
      "use": "enc",
      "crv": "P-256",
      "kid": "mockpass-enc-key",
      "x": "...",
      "y": "..."
    }
  ]
}
```

Provide this file to MockPass either by:
- Copying it into MockPass as `oidc-v2-rp-public.json`, or
- Hosting it and setting: `SP_RP_JWKS_ENDPOINT=http://your-host/jwks.json`

---

## Step 3: Configure WSO2 Keystores

Copy the generated keystores into the WSO2 directory:

```
carbon.p12
enc.p12
```

into:

```
<WSO2_HOME>/repository/resources/security/
```

---

## Build & Deploy

### 1. Build the JAR

```bash
mvn clean package -DskipTests
```

### 2. Deploy to WSO2

```bash
cp target/mockpass-oidc-authenticator-1.0.0.jar \
   <IS_HOME>/repository/components/dropins/
```

Restart WSO2 IS after copying.

---

## Relay Server

MockPass only returns `code` and `state` in its callback. WSO2 needs `sessionDataKey` as a separate URL parameter to continue the authentication flow.

The `sessionDataKey` is embedded inside the `state` value during the PAR request as `state.sessionDataKey`. The relay extracts it and forwards everything to WSO2.

```javascript
// mockpass-relay/index.js
const express = require('express');
const app = express();

app.get('/callback', (req, res) => {
    const { code, state } = req.query;

    if (!code || !state || !state.includes('.')) {
        return res.status(400).send('Invalid callback');
    }

    const dotIndex = state.indexOf('.');
    const actualState    = state.substring(0, dotIndex);
    const sessionDataKey = state.substring(dotIndex + 1);

    const wso2Url = `https://localhost:9443/commonauth` +
        `?code=${encodeURIComponent(code)}` +
        `&state=${encodeURIComponent(actualState)}` +
        `&sessionDataKey=${encodeURIComponent(sessionDataKey)}`;

    res.redirect(wso2Url);
});

app.listen(3000, () => console.log('Relay running on http://localhost:3000'));
```

Start the relay:

```bash
cd mockpass-relay
npm install
node index.js
# Relay running on http://localhost:3000
```

---

## WSO2 Configuration

In the WSO2 Management Console, create a new Identity Provider with the following settings.

**Identity Provider Details:**

| Field | Value |
|---|---|
| Identity Provider Name | `singpass v3` |
| Alias | `mockpass` |

**OIDC Configuration:**

| Field | Value |
|---|---|
| Client ID | `mock` |
| Authorization Endpoint | `http://localhost:5156/singpass/v3/fapi/auth` |
| Token Endpoint | `http://localhost:5156/singpass/v3/fapi/token` |
| Callback URL | `http://localhost:3000/callback` |

**Authenticator Parameters:**

| Parameter | Value |
|---|---|
| `par_endpoint` | `http://localhost:5156/singpass/v3/fapi/par` |
| `signing_keystore` | `/repository/resources/security/carbon.p12` |
| `keystore_password` | `<your-password>` |
| `key_alias` | `mockpass-key` |
| `encryption_keystore` | `/repository/resources/security/enc.p12` |
| `encryption_keystore_password` | `<your-password>` |
| `encryption_key_alias` | `mockpass-enc-key` |

---

## Module Summary

### `MockPassOIDCAuthenticator`

Overrides key methods of `OpenIDConnectAuthenticator` to implement the full FAPI-compliant flow:

| Method | What it does |
|---|---|
| `initiateAuthenticationRequest()` | Generates security tokens, sends PAR request, redirects browser |
| `canHandle()` | Recognises MockPass callbacks by checking for `code` + `sessionDataKey` |
| `processAuthenticationResponse()` | Validates state (CSRF protection), then delegates to parent |
| `getAccessTokenRequest()` | Builds token request with PKCE, DPoP, and client assertion |
| `requestAccessToken()` | Sends token request, intercepts and decrypts JWE ID token |
| `mapIdToken()` | Returns pre-decrypted ID token from context to parent |

---

## FAQ

**Why PAR instead of a normal authorization request?**

Without PAR, all sensitive parameters (state, nonce, PKCE, client assertion) go in the browser URL. PAR sends them server-to-server first and only a short-lived `request_uri` reference goes in the browser — keeping sensitive params out of browser history and logs.

**Why is a relay server needed?**

MockPass only returns `code` and `state` in its callback. WSO2 needs `sessionDataKey` as a separate parameter. The relay bridges this gap by extracting `sessionDataKey` from the `state` value and forwarding it correctly to WSO2.

**Why two keystores?**

The signing key (`carbon.p12`) proves your identity to MockPass via the `client_assertion` JWT. The encryption key (`enc.p12`) decrypts the JWE-wrapped ID token — MockPass encrypts it with your registered public key so only you can read it.

**Why is the DPoP key ephemeral?**

A new EC key pair is generated per session and only lives in memory. Even if an access token is stolen, it cannot be used without the ephemeral private key — which is never stored anywhere.

**Why is `client_assertion` generated twice?**

Once for the PAR request and once for the token request. Each JWT has a 5-minute expiry — by the time the token request is made the original one would be expired. A fresh one is generated each time using the same long-lived signing key from `carbon.p12`.

Happy testing! 🎉