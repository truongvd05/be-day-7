import userModel from "#models/user.model.js";
import revokedTokenModel from "#models/revokedToken.model.js";
import jwtService from "#services/jwtService.js";
import jwtconfig from "#config/jwt.js";
import AuthError from "#utils/AuthError.js";
import bcrypt from "bcrypt";
import responseToken from "#utils/responseToken.js";
import jwt from "jsonwebtoken";
import emailService from "#services/email.service.js";
import queueService from "#services/queue.service.js";

const register = async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || typeof email !== "string" || email.trim().length === 0) {
        return res.error("Email is required and must be valid", 400);
    }
    if (
        !password ||
        typeof password !== "string" ||
        password.trim().length < 6
    ) {
        return res.error("Password must be at least 6 characters", 400);
    }
    try {
        const emailUser = await userModel.findUserByEmail(email);
        if (emailUser && emailUser.length > 0) {
            return next(new AuthError("Email already exists"));
        }
        const result = await userModel.registerUser(email, password);
        const token = jwtService(
            result.insertId,
            jwtconfig.secret,
            jwtconfig.accessTokenTTL,
        );
        const emailToken = jwtService(
            result.insertId,
            jwtconfig.emailSecret,
            jwtconfig.emailTokenTTL,
        );

        // await emailService.sendVerifyEmail(email, emailToken);
        queueService.push("sendVerifyEmail", { token: emailToken });

        res.success(
            {
                user_id: result.insertId,
                email,
            },
            201,
            {
                access_token: token,
                access_token_ttl: 3600,
            },
        );
    } catch (err) {
        return next(err);
    }
};

const login = async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || typeof email !== "string" || email.trim().length === 0) {
        return res.error("Email is required and must be valid", 400);
    }
    if (
        !password ||
        typeof password !== "string" ||
        password.trim().length < 6
    ) {
        return res.error("Password must be at least 6 characters", 400);
    }
    try {
        const user = await userModel.findUserByEmail(email);
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            throw new AuthError("Email hoặc password không đúng");
        }
        const token = responseToken(user);
        await userModel.updateRefreshToken(
            user.id,
            token.refresh_token,
            token.refresh_token_ttl,
        );
        return res.success(user, 200, token);
    } catch (err) {
        return next(err);
    }
};

const logout = async (req, res) => {
    const { jti, exp } = req.auth;

    if (exp <= Math.floor(Date.now() / 1000)) {
        return res.success(null, 204);
    }
    await revokedTokenModel.create({
        jti,
        user_id: req.user.id,
        expired_at: new Date(exp * 1000),
    });
    await userModel.clearRefreshToken(req.user.id);
    return res.success(null, 204);
};

const refreshTokenHandle = async (req, res) => {
    const refreshToken = req.body.refresh_token;
    if (!refreshToken) {
        return res.error("missing refresh_token");
    }
    const user = await userModel.findUserByRefreshToken(refreshToken);
    if (!user) {
        return res.error("Unauthorized", 401);
    }
    const token = responseToken(user);
    await userModel.updateRefreshToken(user.id, refreshtoken, refreshTtl);
    return res.success(
        {
            token,
        },
        200,
    );
};

const verifyEmail = async (req, res, next) => {
    const token = req.body.token;
    if (!token) {
        return res.error("missing token");
    }
    try {
        const payload = jwt.verify(token, jwtconfig.emailSecret);
        const user = await userModel.findUserById(payload.sub);
        if (!user) throw new NotFoundError("User not found");
        if (user.verified_at) {
            throw new AuthError("Email already verified");
        }
        await userModel.verifyEmail(user.id);
        return res.success({ verified: true });
    } catch (err) {
        next(err);
    }
};

const resendVerifyEmail = async (req, res, next) => {
    const user = req.user;
    try {
        if (!user) {
            throw new AuthError("Unauthorized");
        }
        if (user.verified_at) {
            throw new AuthError("Email already verified");
        }
        const token = jwtService(
            user.id,
            jwtconfig.emailSecret,
            jwtconfig.emailTokenTTL,
        );
        await emailService.sendVerifyEmail(user.email, token);
        return res.success({
            message: "Verification email has been resent",
        });
    } catch (err) {
        next(err);
    }
};

export default {
    register,
    login,
    logout,
    refreshTokenHandle,
    verifyEmail,
    resendVerifyEmail,
};
