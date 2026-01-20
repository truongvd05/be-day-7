import jwtService from "#services/jwtService.js";
import jwtconfig from "#config/jwt.js";
import crypto from "crypto";

function responseToken(user) {
    const accessToken = jwtService(
        user.id,
        jwtconfig.secret,
        jwtconfig.accessTokenTTL,
    );
    const refreshtoken = crypto.randomBytes(64).toString("hex");
    const refreshTtl = new Date(Date.now() + jwtconfig.refreshTokenTTL * 1000);
    return {
        access_token: accessToken,
        access_token_ttl: jwtconfig.accessTokenTTL,
        refresh_token: refreshtoken,
        refresh_token_ttl: refreshTtl,
    };
}

export default responseToken;
