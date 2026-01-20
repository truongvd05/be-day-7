import express from "express";

import authController from "#controllers/auth.controller.js";
import authMeRequired from "#middlewares/authRequired.js";

const authRouter = express.Router();

authRouter.post("/register", authController.register);
authRouter.post("/login", authController.login);
authRouter.post("/logout", authMeRequired, authController.logout);
authRouter.post("/refresh-token", authController.refreshTokenHandle);
authRouter.post("/verify-email", authController.verifyEmail);
authRouter.post(
    "/resend-verify-email",
    authMeRequired,
    authController.resendVerifyEmail,
);
authRouter.post(
    "/change-password",
    authMeRequired,
    authController.changePassword,
);

export default authRouter;
