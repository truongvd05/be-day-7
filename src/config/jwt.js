const jwt = {
    secret: process.env.JWT_SECRET,
    emailSecret: process.env.EMAIL_SECRET,
    changePasswordSecret: process.env.PASSWORD_SECRET,
    accessTokenTTL: Number(process.env.ACCESS_TOKEN_TTL),
    refreshTokenTTL: Number(process.env.REFRESH_TOKEN_TTL),
    emailTokenTTL: Number(process.env.EMAIL_TOKEN_TTL),
    changePasswordSecrectTTL: Number(process.env.PASSWORD_TOKEN_TTL),
};

export default jwt;
