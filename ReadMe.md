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
- [Step 3: Configure WSO2 Directory Structure](#step-3-configure-wso2-directory-structure)
- [Step 4: Configure deployment.toml](#step-4-configure-deploymenttoml)
- [Step 5: Build the Project](#step-5-build-the-project)
- [Step 6: Deploy to WSO2](#step-6-deploy-to-wso2)
- [Step 7: Start WSO2 Server](#step-7-start-wso2-server)
- [Step 8: Verify JWKS Endpoint](#step-8-verify-jwks-endpoint)
- [Step 9: Start MockPass](#step-9-start-mockpass-singpass-v3)
- [Step 10: Verify Custom Authenticator](#step-10-verify-custom-authenticator)
- [Step 11: Configure Connection in WSO2 Console](#step-11-configure-connection-in-wso2-console)
- [Module Summary](#module-summary)
- [FAQ](#faq)

---

## Project Layout

```
singpass-v3-implementation/
├── src/
│   └── main/java/com/example/wso2/
│       ├── internal/
│       │   └── CustomAuthenticatorServiceComponent.java  ← OSGi registration + JWKS servlet
│       ├── servlet/
│       │   └── JwksServlet.java                          ← dynamically serves JWKS at /singpass/jwks.json
│       ├── utils/
│       │   └── MockPassUtils.java                        ← cryptographic helpers
│       ├── MockPassConstants.java                        ← shared constants
│       └── MockPassOIDCAuthenticator.java                ← custom authenticator
├── pom.xml
└── .gitignore
```

> **Note:** Keystores (`.p12`) and certificates (`.pem`) are excluded from the repository via `.gitignore` and must be generated locally.

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
- WSO2 Identity Server 6.1.0
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
          - state = sessionDataKey.SINGPASSV3
          - nonce
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
4. MockPass redirects directly to WSO2
        https://localhost:9443/commonauth
        ?code=abc123
        &state=sessionDataKey.SINGPASSV3
        │
        WSO2 calls getContextIdentifier()
          → splits state on '.'
          → extracts sessionDataKey (before the dot)
          → finds the correct auth session
        │
        WSO2 calls canHandle()
          → checks state.endsWith(".SINGPASSV3") ✓
          → this authenticator handles the request
        │
        ▼
5. WSO2 calls processAuthenticationResponse()
        │
        validates state sessionDataKey == originalState  (CSRF check) ✓
        │
        POST ──► MockPass /token      (backchannel)
                 body: code, code_verifier, client_assertion, grant_type
                 header: DPoP
        ◄── {
              "access_token": "xxx",
              "id_token": "eyJ..."    ← encrypted JWE
            }
        │
        decrypts JWE id_token using carbon.p12 (mockpass-enc-key alias)
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

One PKCS12 keystore (`carbon.p12`) is required containing **two EC keypairs** — one for signing and one for encryption. Both are generated directly inside the keystore using `keytool`.

### Generate signing keypair

Signs the `client_assertion` JWT sent to MockPass at both the PAR and token endpoints.

```bash
keytool -genkeypair \
  -alias mockpass-key \
  -keyalg EC \
  -groupname secp256r1 \
  -keystore carbon.p12 \
  -storetype PKCS12 \
  -storepass wso2carbon \
  -dname "CN=mockpass-signing"
```

### Generate encryption keypair

Decrypts the JWE-wrapped ID token returned by MockPass. MockPass encrypts the ID token using your registered public key — only your private key can decrypt it.

```bash
keytool -genkeypair \
  -alias mockpass-enc-key \
  -keyalg EC \
  -groupname secp256r1 \
  -keystore carbon.p12 \
  -storetype PKCS12 \
  -storepass wso2carbon \
  -dname "CN=mockpass-encryption"
```

### Verify both keypairs are in the keystore

```bash
keytool -list -keystore carbon.p12 -storetype PKCS12 -storepass wso2carbon
```

Expected output:
```
Your keystore contains 2 entries
mockpass-enc-key, ...
mockpass-key, ...
```

---

## Step 3: Configure WSO2 Directory Structure

Create the required folder inside your WSO2 directory and copy the keystore there:

```bash
mkdir <IS_HOME>/mockpass-keystores
cp carbon.p12 <IS_HOME>/mockpass-keystores/
```

Final structure:

```
wso2is-6.1.0/
└── mockpass-keystores/
    └── carbon.p12        ← contains both signing and encryption keypairs
```

> **Note:** The `JwksServlet` dynamically builds the JWKS JSON by reading public keys directly from `carbon.p12` at request time.

---

## Step 4: Configure deployment.toml

Add the following to `<IS_HOME>/repository/conf/deployment.toml`:

```toml
[[authentication.custom_authenticator]]
name = "MockPassOIDCAuthenticator"
parameters.keystore = "/singpass-keystores/carbon.p12"
parameters.keystore_password = "wso2carbon"
parameters.key_alias = "mockpass-key"
parameters.encryption_key_alias = "mockpass-enc-key"

[[resource.access_control]]
context = "(.*)/singpass/jwks(.*)"
secure = false
http_method = "GET"
```

This tells WSO2:
- Which alias to use for signing the client assertion JWT (`mockpass-key`)
- Which alias to use for decrypting the JWE ID token (`mockpass-enc-key`)
- Both aliases live in the same `carbon.p12` keystore — one keystore, one password, two aliases
- The JWKS endpoint is publicly accessible without authentication

> **Note:** Keystore paths are relative to `carbon.home` (the WSO2 IS root directory).

---

## Step 5: Build the Project

Run inside the IntelliJ terminal:

```bash
mvn clean install
```

This generates the OSGi bundle JAR file in the `target/` directory.

---

## Step 6: Deploy to WSO2

Copy the generated JAR into WSO2:

```bash
cp target/com.example.wso2.mockpass.authenticator-1.0.0.jar \
   <IS_HOME>/repository/components/dropins/
```

WSO2 will auto-deploy this authenticator on next startup.

---

## Step 7: Start WSO2 Server

```bash
cd <IS_HOME>/bin
sh wso2server.sh
```

---

## Step 8: Verify JWKS Endpoint

Once the server has started, open in a browser:

```
https://localhost:9443/singpass/jwks.json
```

You should see both public keys returned as JSON. This confirms:
- The bundle activated successfully
- The `JwksServlet` loaded public keys from `carbon.p12` and built the JWKS dynamically
- The `deployment.toml` access control entry is applied

---

## Step 9: Start MockPass (Singpass v3)

MockPass simulates the Singpass OIDC provider locally.

```bash
cd mockpass
export FAPI_CLIENT_JWKS_ENDPOINT=https://localhost:9443/singpass/jwks.json
npm start
# MockPass running on http://localhost:5156
```

`FAPI_CLIENT_JWKS_ENDPOINT` tells MockPass where to fetch your public keys for verifying client assertions and encrypting ID tokens. It points directly to the WSO2-hosted endpoint — no separate HTTP server needed.

---

## Step 10: Verify Custom Authenticator

1. Open WSO2 Management Console: `https://localhost:9443/carbon/`
2. Login with admin credentials
3. Navigate to: **Main → Identity → Identity Providers → List**
4. You should see `singpassv3` listed with `MockPassOIDCAuthenticator` configured

---

## Step 11: Configure Connection in WSO2 Console

1. Go to `https://localhost:9443/carbon/`
2. **Main → Identity → Identity Providers → Add**
3. Set **Identity Provider Name**: `singpassv3`
4. Expand **Federated Authenticators → Custom Authenticators**
5. Tick **Enable** and **Default**, select `MockPassOIDCAuthenticator`
6. Fill in the following fields:

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
| Callback URL | `https://localhost:9443/commonauth` |

**Additional Parameters:**

| Parameter | Value |
|---|---|
| `par_endpoint` | `http://localhost:5156/singpass/v3/fapi/par` |

7. Click **Register**

Then link to your app:
1. **Main → Identity → Service Providers → List → testapp → Edit**
2. **Local & Outbound Authentication → Advanced Configuration**
3. In Step 1, under **Federated Authenticators** → Add `singpassv3`
4. Click **Update**

---

## Module Summary

### `MockPassOIDCAuthenticator`

Overrides key methods of `OpenIDConnectAuthenticator`:

| Method | Why overridden | What it does |
|---|---|---|
| `initiateAuthenticationRequest()` | Parent does standard OIDC redirect; we need PAR flow | Generates all security tokens, encrypts the ephemeral DPoP private key via `CryptoUtil` and stores it in context, sends PAR request backchannel, redirects browser to MockPass with only `client_id` and `request_uri` |
| `getContextIdentifier()` | Parent splits state on `,` but Singpass rejects `,`; our delimiter is `.` | Splits state on `.` and extracts `sessionDataKey` (before the dot) so WSO2 can find the correct auth session |
| `canHandle()` | Parent checks `state.split(",")[1].equals("OIDC")` which always fails for our state format | Checks `state.endsWith(".SINGPASSV3")` to correctly identify Singpass callbacks |
| `getAccessTokenRequest()` | Parent uses client_secret; Singpass requires private_key_jwt + PKCE + DPoP | Builds token POST body with authorization code, PKCE verifier, client assertion JWT, and DPoP proof header |
| `requestAccessToken()` | Parent cannot parse encrypted JWE id_token | Calls parent to exchange code for tokens, then intercepts and decrypts the JWE id_token, stores decrypted JWT in context |
| `mapIdToken()` | Parent reads encrypted token from response; we need the decrypted one | Returns pre-decrypted id_token from context so parent can validate nonce and extract claims normally |
| `getConfigurationProperties()` | Need to add PAR endpoint field and remove unused client secret field | Inherits parent fields, removes `ClientSecret`, adds `par_endpoint` |

### `JwksServlet`

A simple `HttpServlet` registered via OSGi `HttpService` at bundle activation. On each GET request to `/singpass/jwks.json`, it dynamically loads public keys from `carbon.p12`, converts them to JWK format using Nimbus JOSE, and returns the combined JWKS JSON — no static file involved. Keystore path, password, and aliases are passed via constructor from `CustomAuthenticatorServiceComponent`.

### `CustomAuthenticatorServiceComponent`

OSGi DS component that activates the bundle. Registers the `MockPassOIDCAuthenticator` as an `ApplicationAuthenticator` OSGi service. Reads keystore configuration from `deployment.toml` via `FileBasedConfigurationBuilder` and passes it to `JwksServlet` via constructor. Registers the servlet via `HttpService` using the same pattern as WSO2's `FrameworkServiceComponent`.

---

## FAQ

**Why PAR instead of a normal authorization request?**

Without PAR, all sensitive parameters (state, nonce, PKCE, client assertion) go in the browser URL. PAR sends them server-to-server first — only a short-lived `request_uri` reference goes in the browser, keeping sensitive params out of browser history and logs.

**Why one keystore with two keypairs?**

Both the signing key (`mockpass-key`) and encryption key (`mockpass-enc-key`) live in the same `carbon.p12` keystore — one file, one password, two aliases. The signing key proves your identity to MockPass via the `client_assertion` JWT. The encryption key decrypts the JWE-wrapped ID token.

**Why is the JWKS hosted inside WSO2 instead of a separate server?**

The `JwksServlet` is registered as an OSGi servlet inside WSO2 at startup — no external process or port needed. It dynamically builds the JWKS JSON by reading public keys directly from `carbon.p12` at request time, so no static `jwks.json` file is required. MockPass fetches keys directly from `https://localhost:9443/singpass/jwks.json`, the same host and port as the rest of the authentication flow.

**Why is the DPoP key ephemeral?**

A new EC key pair is generated per session. The private key is encrypted using WSO2's `CryptoUtil` before being stored in `AuthenticationContext` — it can only be decrypted by the same WSO2 instance. Even if an access token is intercepted, it cannot be used without this ephemeral private key.

**How is the ephemeral DPoP private key protected?**

The ephemeral DPoP private key is encrypted using WSO2's internal `CryptoUtil` (the same mechanism WSO2's `KeyStoreManager` uses to encrypt keystore passwords) before being stored in `AuthenticationContext`. Even if the session is serialized to the database, the private key remains encrypted and can only be decrypted by the same WSO2 instance.

**What does `FAPI_CLIENT_JWKS_ENDPOINT` do?**

It tells MockPass where to fetch your public JWKS. MockPass uses your public keys to verify `client_assertion` signatures and to encrypt the ID token so only you can decrypt it with your private key.

**Why is `,` not used as the state delimiter?**

WSO2's default state format is `sessionDataKey,OIDC`. Singpass strictly validates the state parameter against the pattern `[A-Za-z0-9/+_-=.]+` — the `,` character is not in this pattern, causing the PAR request to be rejected with HTTP 400. We use `.` as the delimiter instead since it is valid per the Singpass spec, giving a state format of `sessionDataKey.SINGPASSV3`.

**What is different from Singpass v2?**

Singpass v3 (FAPI) adds several security layers on top of v2 — PAR keeps auth params out of the browser URL, PKCE prevents code interception, and DPoP binds tokens to the specific client making the request.

Happy testing! 🎉