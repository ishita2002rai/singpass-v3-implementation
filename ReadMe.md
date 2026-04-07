# MockPass OIDC Authenticator (WSO2 + Singpass v2)

This project implements a custom OIDC authenticator for WSO2 Identity Server to integrate with **MockPass (Singpass v2 / NDI OIDC)** using ES256 signing and ECDH encryption.

---

## Getting Started

### 1. Clone the Repository

Clone the project from GitHub to your local machine:

```bash
git clone https://github.com/ishita2002rai/mockpass-oidc-authenticator-singpass-.git
cd mockpass-oidc-authenticator-singpass-
```


## Open the Project in IntelliJ

1. Open IntelliJ IDEA
2. Click **File → Open**
3. Select the cloned project folder
4. Wait for Maven dependencies to load

All further steps (build, run commands) can be done using the **IntelliJ Terminal**

---

## Step 2: Generate Cryptographic Keys

This project requires:

* **Signing key (ES256)** → for JWT client assertion
* **Encryption key (ECDH)** → for decrypting ID Token

Run the following commands in terminal:

### Signing Keys

```bash
openssl ecparam -name prime256v1 -genkey -noout -out sig-key.pem
openssl ec -in sig-key.pem -pubout -out sig-pub.pem

openssl req -new -x509 \
  -key sig-key.pem \
  -out sig-cert.pem \
  -days 365 \
  -subj "/CN=mockpass-signing"

openssl pkcs12 -export \
  -inkey sig-key.pem \
  -in sig-cert.pem \
  -out carbon.p12 \
  -name mockpass-key
```

### Encryption Keys

```bash
openssl ecparam -name prime256v1 -genkey -noout -out enc-key.pem
openssl ec -in enc-key.pem -pubout -out enc-pub.pem

openssl req -new -x509 \
  -key enc-key.pem \
  -out enc-cert.pem \
  -days 365 \
  -subj "/CN=mockpass-encryption"

openssl pkcs12 -export \
  -inkey enc-key.pem \
  -in enc-cert.pem \
  -out enc.p12 \
  -name mockpass-enc-key
```

These commands:

* Generate EC key pairs
* Create self-signed certificates
* Package them into `.p12` keystores for WSO2

---

## Step 3: Configure WSO2 Keystores

Copy the generated files:

```
carbon.p12
enc.p12
```

into:

```
<WSO2_HOME>/repository/resources/security/
```

---

## Step 4: Configure `deployment.toml`

Add the following configuration in your WSO2 `deployment.toml`:

```toml
[[authentication.custom_authenticator]]
name = "MockPassOIDCAuthenticator"

parameters.signing_keystore = "/repository/resources/security/carbon.p12"
parameters.keystore_password = "wso2carbon"
parameters.key_alias = "mockpass-key"

parameters.encryption_keystore = "/repository/resources/security/enc.p12"
parameters.encryption_keystore_password = "wso2carbon"
parameters.encryption_key_alias = "mockpass-enc-key"
```

This tells WSO2:

* Which key to use for signing JWT
* Which key to use for decrypting ID tokens

---

## Step 5: Generate JWKS

Run the Node.js script:

```bash
node generate-jwks.js
```

This generates:

```
jwks.json
```

JWKS (JSON Web Key Set) contains:

* Public signing key
* Public encryption key

MockPass uses this to:

* Verify your client signature
* Encrypt ID tokens sent to your app

---

## Step 6: Host JWKS

You must expose `jwks.json` over HTTP so MockPass can access it.

Run:

```bash
npx http-server -p 8080
```

Now your JWKS is available at:

```
http://127.0.0.1:8080/jwks.json
```

---

## Step 7: Start MockPass (Singpass v2)

MockPass simulates the Singpass OIDC provider locally.

Run:

```bash
export SP_RP_JWKS_ENDPOINT=http://127.0.0.1:8080/jwks.json
export SHOW_LOGIN_PAGE=true

npx -y @opengovsg/mockpass start
```

### What these configs do:

* `SP_RP_JWKS_ENDPOINT`
  → Tells MockPass where to fetch your public keys

* `SHOW_LOGIN_PAGE=true`
  → Enables UI login instead of silent authentication

---

## 🛠️ Step 8: Build the Project

Run inside IntelliJ terminal:

```bash
mvn clean install
```

This generates the OSGi bundle (JAR file)

---

## 📦 Step 9: Deploy to WSO2

Copy the generated file:

```bash
target/authenticator-1.0-SNAPSHOT.jar
```

into:

```bash
<WSO2_HOME>/repository/components/dropins/
```

WSO2 will auto-deploy this authenticator



## Step 10: Start WSO2 Server

Inside WSO2 `<WSO2_HOME>/bin` directory, run:

```bash
sh wso2server.sh
```

---

## Step 11: Verify & Configure Custom Authenticator

Once the server is started:

1. Open WSO2 Management Console:

 ```bash
   https://localhost:9443/console
   ```

2. Login with admin credentials

3. Navigate to:

```bash
   Connections → New Connection → Custom Authenticator (Plugin)
   ```

5. You will see:

```bash
MockPassOIDCAuthenticator
```

---

## Step 12: Configure Endpoints

1. Click on **MockPassOIDCAuthenticator**

2. Fill in the required endpoints:

```bash
Authorization Endpoint:
http://localhost:5156/singpass/v2/auth

Token Endpoint:
http://localhost:5156/singpass/v2/token

JWKS Endpoint:
http://localhost:5156/singpass/v2/.well-known/keys

OIDC Discovery Endpoint:
http://localhost:5156/singpass/v2/.well-known/openid-configuration
```

3. Enter:

* **Client ID** → any value (MockPass accepts any)
* **Callback URL** → your WSO2 callback URL

---

## What this does

* WSO2 will redirect users to MockPass `/auth`
* Exchange code at `/token`
* Validate keys via JWKS
* Use your custom authenticator for:

    * JWT client assertion
    * ID token decryption

---

## 🎯 Final Result

Your flow is now:

WSO2 → MockPass (Singpass v2) → WSO2
with:

* ES256 signed client assertion
* Encrypted ID token (ECDH-ES)
* Custom authenticator handling everything

