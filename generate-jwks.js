const fs = require("fs");
const { importSPKI, exportJWK } = require("jose");

(async () => {
    // 🔐 SIGNING KEY
    const sigPem = fs.readFileSync("sig-pub.pem", "utf8");
    const sigKey = await exportJWK(await importSPKI(sigPem, "ES256"));

    sigKey.use = "sig";
    sigKey.alg = "ES256";
    sigKey.kid = "mockpass-key";

    // 🔐 ENCRYPTION KEY
    const encPem = fs.readFileSync("enc-pub.pem", "utf8");
    const encKey = await exportJWK(await importSPKI(encPem, "ES256"));

    encKey.use = "enc";
    encKey.alg = "ECDH-ES+A256KW";
    encKey.kid = "mockpass-enc-key";

    // 📦 COMBINE BOTH
    const jwks = {
        keys: [sigKey, encKey]
    };

    fs.writeFileSync("jwks.json", JSON.stringify(jwks, null, 2));

    console.log("JWKS generated with BOTH sig + enc keys");

})();