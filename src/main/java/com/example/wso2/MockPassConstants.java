package com.example.wso2;

/**
 * Compile-time constants shared across the MockPass OIDC authenticator classes.
 *
 * <p>All fields are {@code public static final} so that {@link MockPassOIDCAuthenticator}
 * and {@link utils.MockPassUtils} can reference them without any runtime cost.
 */
public final class MockPassConstants {

    private MockPassConstants() {
        // Utility class – do not instantiate.
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    public static final String AUTHENTICATOR_NAME          = "MockPassOIDCAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "MockPass OIDC Authenticator";

    // ── OAuth / OIDC ──────────────────────────────────────────────────────────

    public static final String CLIENT_ASSERTION_TYPE  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String RESPONSE_TYPE_CODE     = "code";
    public static final String SCOPE_OPENID_UINFIN    = "openid uinfin";
    public static final String CODE_CHALLENGE_METHOD  = "S256";
    public static final String DPOP_JWT_TYPE          = "dpop+jwt";
    public static final String TOKEN_PATH_SEGMENT     = "/token";
    public static final String HASH_ALGORITHM_SHA256  = "SHA-256";

    // ── Request / response parameter names ───────────────────────────────────

    public static final String PARAM_SESSION_DATA_KEY = "sessionDataKey";
    public static final String PARAM_STATE            = "state";
    public static final String PARAM_CODE             = "code";

    public static final String PARAM_KEY_CLIENT_ID             = "client_id";
    public static final String PARAM_KEY_REDIRECT_URI          = "redirect_uri";
    public static final String PARAM_KEY_RESPONSE_TYPE         = "response_type";
    public static final String PARAM_KEY_SCOPE                 = "scope";
    public static final String PARAM_KEY_NONCE                 = "nonce";
    public static final String PARAM_KEY_CODE_CHALLENGE        = "code_challenge";
    public static final String PARAM_KEY_CODE_CHALLENGE_METHOD = "code_challenge_method";
    public static final String PARAM_KEY_CLIENT_ASSERTION_TYPE = "client_assertion_type";
    public static final String PARAM_KEY_CLIENT_ASSERTION      = "client_assertion";
    public static final String PARAM_KEY_CODE_VERIFIER         = "code_verifier";
    public static final String PARAM_KEY_REQUEST_URI           = "request_uri";

    // ── HTTP ──────────────────────────────────────────────────────────────────

    public static final String HTTP_METHOD_POST             = "POST";
    public static final String HTTP_HEADER_DPOP             = "DPoP";
    public static final String HTTP_HEADER_CONTENT_TYPE     = "Content-Type";
    public static final String HTTP_HEADER_CONTENT_LENGTH   = "Content-Length";
    public static final String CONTENT_TYPE_FORM            = "application/x-www-form-urlencoded";

    // ── DPoP JWT claim names ──────────────────────────────────────────────────

    public static final String CLAIM_HTU = "htu";
    public static final String CLAIM_HTM = "htm";

    // ── Authenticator config parameter names ──────────────────────────────────

    public static final String PARAM_PAR_ENDPOINT            = "par_endpoint";
    public static final String PARAM_SIGNING_KEYSTORE        = "signing_keystore";
    public static final String PARAM_KEYSTORE_PASSWORD       = "keystore_password";
    public static final String PARAM_KEY_ALIAS               = "key_alias";
    public static final String PARAM_ENCRYPTION_KEYSTORE     = "encryption_keystore";
    public static final String PARAM_ENCRYPTION_KEYSTORE_PASS = "encryption_keystore_password";
    public static final String PARAM_ENCRYPTION_KEY_ALIAS    = "encryption_key_alias";

    // ── PAR endpoint UI metadata ──────────────────────────────────────────────

    public static final String PAR_ENDPOINT_DISPLAY_NAME = "PAR Endpoint";
    public static final String PAR_ENDPOINT_DESCRIPTION  =
            "Pushed Authorization Request endpoint for FAPI flow";

    // ── Context property keys ─────────────────────────────────────────────────

    public static final String CTX_EPHEMERAL_KEY = "EPHEMERAL_KEY";
    public static final String CTX_CODE_VERIFIER = "CODE_VERIFIER";
    public static final String CTX_STATE         = "STATE";
    public static final String CTX_NONCE         = "NONCE";

    // ── System properties ─────────────────────────────────────────────────────

    public static final String SYSTEM_PROPERTY_CARBON_HOME = "carbon.home";

    // ── Crypto ────────────────────────────────────────────────────────────────

    public static final String EC_CURVE         = "secp256r1";
    public static final String KEYSTORE_TYPE    = "PKCS12";
    public static final String KEY_ALGORITHM_EC = "EC";
    public static final int    EC_COORD_SIZE    = 32;
    public static final long   JWT_TTL_MS       = 5 * 60 * 1000L;
    public static final long   DPOP_TTL_SEC     = 120L;
}