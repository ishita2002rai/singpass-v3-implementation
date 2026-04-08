# Singpass v3 OIDC Authenticator for WSO2 Identity Server

A custom WSO2 Identity Server authenticator implementing a **FAPI-compliant OIDC flow** for MockPass (Singpass v3).

It extends WSO2's built-in `OpenIDConnectAuthenticator` and adds the full security stack required by Singpass — PAR, PKCE, DPoP, private-key JWT client authentication, and JWE ID token decryption.

---

## Table of Contents

- [Project Layout](#project-layout)
- [Security Features](#security-features)
- [Prerequisites](#prerequisites)
- [Authentication Flow](#authentication-flow)
- [Step 1: Clone & Open the Project](#step-1-clone--open-the-project)
- [Step 2: Generate EC Keys & Keystores](#step-2-generate-ec-keys--keystores)
- [Step 3: Configure WSO2 Keystores](#step-3-configure-wso2-keystores)
- [Step 4: Configure deployment.toml](#step-4-configure-deploymenttoml)
- [Step 5: Generate JWKS](#step-5-generate-jwks)
- [Step 6: Host JWKS](#step-6-host-jwks)
- [Step 7: Start MockPass](#step-7-start-mockpass-singpass-v3)
- [Step 8: Start Relay Server](#step-8-start-relay-server)
- [Step 9: Build the Project](#step-9-build-the-project)
- [Step 10: Deploy to WSO2](#step-10-deploy-to-wso2)
- [Step 11: Start WSO2 Server](#step-11-start-wso2-server)
- [Step 12: Verify Custom Authenticator](#step-12-verify-custom-authenticator)
- [Step 13: Configure Connection in WSO2 Console](#step-13-configure-connection-in-wso2-console)
- [Module Summary](#module-summary)
- [FAQ](#faq)

---

## Project Layout

```
singpass-v3-implementation/
├── src/
│   └── main/java/com/example/wso2/
│       └── internal/
│           ├── CustomAuthenticatorServiceComponent.java  ← OSGi registration
│           ├── JWTUtil.java                              ← JWT helpers
│           └── MockPassOIDCAuthenticator.java            ← custom authenticator
├── mockpass-relay/
│   ├── index.js                                          ← relay server
│   ├── package.json
│   └── package-lock.json
├── generate-jwks.js                                      ← JWKS export script
├── pom.xml
└── .gitignore
```

> **Note:** Keystores (`.p12`), certificates (`.pem`), private keys (`.key`), and `jwks.json` are excluded from the repository via `.gitignore` and must be generated locally.

---

## Security Features

| Feature | Description |
|---|---|
| **PAR** | Pushed Authorization Requests — auth params sent via backchannel before browser redirect |
| **PKCE** | Proof Key for Code Exchange (S256) — prevents authorization code interception |
| **DPoP** | Demonstrating Proof of Possession — binds tokens to the client using an ephemeral EC key per session |
| **Private-key JWT** | Client authentication using a signed JWT instead of a shared secret |
| **JWE** | Encrypted ID token (ECDH-ES) — decrypted with a local EC private key |

---

## Prerequisites

- JDK 11+
- Apache Maven 3.8+
- Node.js 16+
- WSO2 Identity Server 7.2.0
- MockPass running locally on port `5156`
- `openssl` — bundled with most Unix systems
- IntelliJ IDEA (recommended)

---

## Authentication Flow

```
1. User clicks "Login with Singpass"
        │
        ▼
2. WSO2 calls initiateAuthenticationRequest()
        │
        generates:
          - state, nonce
          - codeVerifier, codeChallenge (PKCE)
          - ephemeral EC key pair (DPoP)
          - clientAssertion (signed JWT)
          - DPoP proof JWT
        │
        POST ──► MockPass /par        (backchannel — user never sees this)
                 body: client_id, redirect_uri, state, nonce,
                       code_challenge, client_assertion
                 header: DPoP
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
        http://localhost:3000/callback
        ?code=abc123
        &state=uuid.sessionDataKey
        │
        Relay splits state on '.'
        actualState    = "uuid"
        sessionDataKey = "12bc982a-..."
        │
        Relay redirects ──► WSO2 /commonauth
                            ?code=abc123
                            &state=uuid
                            &sessionDataKey=12bc982a-...
        │
        ▼
5. WSO2 calls processAuthenticationResponse()
        │
        validates state == originalState  (CSRF check) ✓
        │
        POST ──► MockPass /token      (backchannel)
                 body: code, code_verifier, client_assertion, grant_type
                 header: DPoP
        ◄── {
              "access_token": "xxx",
              "id_token": "eyJ..."    ← encrypted JWE
            }
        │
        decrypts JWE id_token using enc.p12
        extracts inner SignedJWT
        validates nonce ✓
        extracts claims (NRIC / uinfin)
        builds AuthenticatedUser
        │
        ▼
6. WSO2 creates session, issues its own tokens to your app
        User is logged in ✓
```

---

## Step 1: Clone & Open the Project

```bash
git clone https://github.com/ishita2002rai/singpass-v3-implementation.git
cd singpass-v3-implementation
```

**Open in IntelliJ IDEA:**
- Click `File → Open`
- Select the cloned project folder
- Wait for Maven dependencies to load

All further steps can be run from the IntelliJ terminal.

---

## Step 2: Generate EC Keys & Keystores

Two EC keystores are required — one for **signing** and one for **encryption**.

### Signing Keystore (`carbon.p12`)

Signs the `client_assertion` JWT sent to MockPass at both the PAR and token endpoints.

```bash
# Generate EC private key
openssl ecparam -name prime256v1 -genkey -noout -out ec-private.key

# Extract public key
openssl ec -in ec-private.key -pubout -out ec-public.key

# Generate self-signed certificate
openssl req -new -x509 \
  -key ec-private.key \
  -out ec-cert.pem \
  -days 365 \
  -subj "/CN=mockpass-signing"

# Package into PKCS12 keystore
openssl pkcs12 -export \
  -inkey ec-private.key \
  -in ec-cert.pem \
  -out carbon.p12 \
  -name mockpass-key
```

### Encryption Keystore (`enc.p12`)

Decrypts the JWE-wrapped ID token returned by MockPass. MockPass encrypts the ID token using your registered public key — only your private key can decrypt it.

```bash
# Generate EC private key
openssl ecparam -name prime256v1 -genkey -noout -out enc-key.pem

# Extract public key
openssl ec -in enc-key.pem -pubout -out enc-pub.pem

# Generate self-signed certificate
openssl req -new -x509 \
  -key enc-key.pem \
  -out enc-cert.pem \
  -days 365 \
  -subj "/CN=mockpass-encryption"

# Package into PKCS12 keystore
openssl pkcs12 -export \
  -inkey enc-key.pem \
  -in enc-cert.pem \
  -out enc.p12 \
  -name mockpass-enc-key
```

These commands generate EC key pairs, create self-signed certificates, and package them into `.p12` keystores for WSO2.

---

## Step 3: Configure WSO2 Keystores

Create a `mockpass-keystores` folder inside your WSO2 directory and copy both keystores there:

```bash
mkdir <IS_HOME>/mockpass-keystores
cp carbon.p12 enc.p12 <IS_HOME>/mockpass-keystores/
```

Final structure:

```
wso2is-7.2.0/
└── mockpass-keystores/
    ├── carbon.p12
    └── enc.p12
```

---

## Step 4: Configure deployment.toml

Add the following to `<IS_HOME>/repository/conf/deployment.toml`:

```toml
[[authentication.custom_authenticator]]
name = "MockPassOIDCAuthenticator"
parameters.signing_keystore = "/mockpass-keystores/carbon.p12"
parameters.keystore_password = "wso2carbon"
parameters.key_alias = "mockpass-key"
parameters.encryption_keystore = "/mockpass-keystores/enc.p12"
parameters.encryption_keystore_password = "wso2carbon"
parameters.encryption_key_alias = "mockpass-enc-key"
```

This tells WSO2:
- Which key to use for signing the client assertion JWT
- Which key to use for decrypting the JWE ID token

> **Note:** Keystore paths are relative to `carbon.home` (the WSO2 IS root directory).

---

## Step 5: Generate JWKS

The `jwks.json` contains your **public keys** and is provided to MockPass so it can verify your client assertion signatures and encrypt the ID token for you.

```bash
node generate-jwks.js
```

This generates `jwks.json` with two entries:

```json
{
  "keys": [
    { "kty": "EC", "use": "sig", "crv": "P-256", "kid": "mockpass-key", "x": "...", "y": "..." },
    { "kty": "EC", "use": "enc", "crv": "P-256", "kid": "mockpass-enc-key", "x": "...", "y": "..." }
  ]
}
```

MockPass uses this to:
- Verify your client assertion signature
- Encrypt ID tokens sent to your app

---

## Step 6: Host JWKS

MockPass needs to fetch your `jwks.json` over HTTP. Serve it on port 8080:

```bash
npx http-server . -p 8080
# JWKS available at http://127.0.0.1:8080/jwks.json
```

---

## Step 7: Start MockPass (Singpass v3)

MockPass simulates the Singpass OIDC provider locally.

```bash
cd mockpass
export FAPI_CLIENT_JWKS_ENDPOINT=http://127.0.0.1:8080/jwks.json
npm start
# MockPass running on http://localhost:5156
```

`FAPI_CLIENT_JWKS_ENDPOINT` tells MockPass where to fetch your public keys for verifying client assertions and encrypting ID tokens.

---

## Step 8: Start Relay Server

The relay bridges MockPass's callback with WSO2's expected parameters. MockPass returns only `code` and `state` — the relay extracts `sessionDataKey` from `state` and forwards it to WSO2.

```bash
cd mockpass-relay
node index.js
# Relay running on http://localhost:3000
```

---

## Step 9: Build the Project

Run inside the IntelliJ terminal:

```bash
mvn clean install
```

This generates the OSGi bundle JAR file in the `target/` directory.

---

## Step 10: Deploy to WSO2

Copy the generated JAR into WSO2:

```bash
cp target/authenticator-1.0-SNAPSHOT.jar \
   <IS_HOME>/repository/components/dropins/
```

WSO2 will auto-deploy this authenticator on next startup.

---

## Step 11: Start WSO2 Server

```bash
cd <IS_HOME>/bin
sh wso2server.sh
```

---

## Step 12: Verify Custom Authenticator

Once the server has started:

1. Open WSO2 Management Console: `https://localhost:9443/console`
2. Login with admin credentials
3. Navigate to: **Connections → New Connection → Custom Authenticator (Plugin)**
4. You should see `MockPassOIDCAuthenticator` listed

---

## Step 13: Configure Connection in WSO2 Console

Click on `MockPassOIDCAuthenticator` and fill in the required fields:

**Endpoints:**

| Field | Value |
|---|---|
| Authorization Endpoint | `http://localhost:5156/singpass/v3/fapi/auth` |
| Token Endpoint | `http://localhost:5156/singpass/v3/fapi/token` |
| JWKS Endpoint | `http://localhost:5156/singpass/v3/fapi/.well-known/jwks` |
| OIDC Discovery Endpoint | `http://localhost:5156/singpass/v3/fapi/.well-known/openid-configuration` |

**Other fields:**

| Field | Value |
|---|---|
| Client ID | `mock` (MockPass accepts any value) |
| Callback URL | `http://localhost:3000/callback` |

**Additional Parameters:**

| Parameter | Value |
|---|---|
| `par_endpoint` | `http://localhost:5156/singpass/v3/fapi/par` |

---

## Relay Server

MockPass returns only `code` and `state` in its callback. WSO2 needs `sessionDataKey` as a separate URL parameter to continue the flow. The `sessionDataKey` is embedded inside `state` during the PAR request as `state.sessionDataKey` — the relay extracts it and forwards everything correctly to WSO2.



---

## Module Summary

### `MockPassOIDCAuthenticator`

Overrides key methods of `OpenIDConnectAuthenticator`:

| Method | What it does |
|---|---|
| `initiateAuthenticationRequest()` | Generates all security tokens, sends PAR request, redirects browser to MockPass |
| `canHandle()` | Recognises MockPass callbacks — checks for both `code` and `sessionDataKey` |
| `processAuthenticationResponse()` | Validates state (CSRF protection), then delegates to parent |
| `getAccessTokenRequest()` | Builds token POST body with code, PKCE verifier, client assertion and DPoP header |
| `requestAccessToken()` | Calls parent to send token request, then intercepts and decrypts the JWE ID token |
| `mapIdToken()` | Returns pre-decrypted ID token from context so parent can validate nonce and extract claims |

---

## FAQ

**Why PAR instead of a normal authorization request?**

Without PAR, all sensitive parameters (state, nonce, PKCE, client assertion) go in the browser URL. PAR sends them server-to-server first — only a short-lived `request_uri` reference goes in the browser, keeping sensitive params out of browser history and logs.

**Why is a relay server needed?**

MockPass only returns `code` and `state` in its callback. WSO2 needs `sessionDataKey` as a separate parameter to resume the session. The relay extracts `sessionDataKey` from the `state` value and forwards it correctly to WSO2.

**Why two keystores?**

The signing key (`carbon.p12`) proves your identity to MockPass via the `client_assertion` JWT. The encryption key (`enc.p12`) decrypts the JWE-wrapped ID token — MockPass encrypts it with your registered public key so only you can read it.

**Why is the DPoP key ephemeral?**

A new EC key pair is generated per session and lives only in memory. Even if an access token is intercepted, it cannot be used without the ephemeral private key — which is never stored anywhere.

**Why is `client_assertion` generated twice?**

Once for the PAR request and once for the token request. Each JWT has a 5-minute expiry — by the time the token request is made the original one would be expired. A fresh assertion is generated each time using the same long-lived signing key from `carbon.p12`.

**What does `FAPI_CLIENT_JWKS_ENDPOINT` do?**

It tells MockPass where to fetch your public JWKS. MockPass uses your public keys to verify `client_assertion` signatures and to encrypt the ID token so only you can decrypt it with your private key.

**Why is `sessionDataKey` embedded in `state`?**

MockPass only passes back whatever `state` value it received — it won't add extra parameters. By embedding `sessionDataKey` inside `state` as `state.sessionDataKey`, we piggyback the WSO2 session reference through MockPass's callback without MockPass needing to know about it.

**What is different from Singpass v2?**

Singpass v3 (FAPI) adds several security layers on top of v2 — PAR keeps auth params out of the browser URL, PKCE prevents code interception, and DPoP binds tokens to the specific client making the request. The v3 flow also requires a relay server because of how `sessionDataKey` needs to be handled.

Happy testing! 🎉