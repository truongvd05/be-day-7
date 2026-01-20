import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

const jwtService = (userid, secret, expiresIn) => {
    const now = Math.floor(Date.now() / 1000);
    const token = jwt.sign(
        {
            sub: userid,
            jti: randomUUID(),
            iat: now,
            exp: now + expiresIn,
        },
        secret,
    );
    return token;
};

export default jwtService;
