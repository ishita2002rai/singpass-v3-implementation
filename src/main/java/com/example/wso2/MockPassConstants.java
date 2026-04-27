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
    public static final String PARAM_KEYSTORE             = "keystore";
    public static final String PARAM_KEYSTORE_PASSWORD    = "keystore_password";
    public static final String PARAM_KEY_ALIAS            = "key_alias";
    public static final String PARAM_ENCRYPTION_KEY_ALIAS = "encryption_key_alias";
    // ── PAR endpoint UI metadata ──────────────────────────────────────────────

    public static final String PAR_ENDPOINT_DISPLAY_NAME = "PAR Endpoint";
    public static final String PAR_ENDPOINT_DESCRIPTION  =
            "Pushed Authorization Request endpoint for FAPI flow";

    // ── Context property keys ─────────────────────────────────────────────────

    public static final String CTX_EPHEMERAL_KEY_PUBLIC    = "EPHEMERAL_KEY_PUBLIC";
    public static final String CTX_EPHEMERAL_KEY_ENCRYPTED = "EPHEMERAL_KEY_ENCRYPTED";
    public static final String CTX_CODE_VERIFIER = "CODE_VERIFIER";

    // ── System properties ─────────────────────────────────────────────────────

    public static final String SYSTEM_PROPERTY_CARBON_HOME = "carbon.home";

    // ── Crypto ────────────────────────────────────────────────────────────────

    public static final String EC_CURVE         = "secp256r1";
    public static final String KEYSTORE_TYPE    = "PKCS12";
    public static final String KEY_ALGORITHM_EC = "EC";
    public static final long   JWT_TTL_MS       = 5 * 60 * 1000L;
    public static final long   DPOP_TTL_SEC     = 120L;

    // ── State format ──────────────────────────────────────────────────────────────

    public static final String STATE_DELIMITER        = ".";
    public static final String STATE_SINGPASSV3_SUFFIX = ".SINGPASSV3";
    public static final String STATE_DELIMITER_REGEX = "\\.";

    // ── PAR HTTP timeouts ─────────────────────────────────────────────────────────
    public static final int PAR_CONNECT_TIMEOUT_MS = 5000;
    public static final int PAR_READ_TIMEOUT_MS    = 10000;

    // ── Nonce ─────────────────────────────────────────────────────────────────────
    public static final String OIDC_FEDERATION_NONCE  = "oidc_federation_nonce";

    // ── JWKS servlet ──────────────────────────────────────────────────────────
    public static final String JWKS_SERVLET_URL = "/singpass/jwks.json";

    // ── JWKS generation ───────────────────────────────────────────────────────────
    public static final String SIG_ALGORITHM = "ES256";
    public static final String ENC_ALGORITHM = "ECDH-ES+A256KW";

}
