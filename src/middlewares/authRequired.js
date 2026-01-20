import jwt from "jsonwebtoken";
import jwtconfig from "#config/jwt.js";
import userModel from "#models/user.model.js";
import revokedTokenModel from "#models/revokedToken.model.js";

const authMeRequired = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.error({ message: "Missing or invalid token" }, 401);
        }
        const access_token = req.headers.authorization.split(" ")[1].trim();
        const payload = jwt.verify(access_token, jwtconfig.secret);
        if (!payload.jti) {
            return res.error("Invalid token (missing jti)", 401);
        }
        const isRevoked = await revokedTokenModel.existsByJti(payload.jti);
        if (isRevoked) {
            return res.error("Token revoked", 401);
        }
        const currentUser = await userModel.findUserById(payload.sub);
        if (!currentUser) {
            return res.error({ message: "User not found" }, 401);
        }
        req.user = currentUser;
        req.auth = {
            token: access_token,
            jti: payload.jti,
            exp: payload.exp,
            sub: payload.sub,
        };
        next();
    } catch (err) {
        console.log(err);
        return res.error("Unauthorized", 401);
    }
};

export default authMeRequired;
