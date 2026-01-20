import jwt from "jsonwebtoken";
import { ERROR_MESSAGE, HTTP_STATUS } from "#config/constants.js";

const errorHandle = (err, _, res, next) => {
    let status = HTTP_STATUS.INTERNAL_SERVER_ERROR;
    let errorMessage = err.message || String(err);
    if (err instanceof jwt.TokenExpiredError) {
        return res.error(
            {
                message:
                    ERROR_MESSAGE.TOKEN_EXPIRED || "Verify link has expired",
            },
            HTTP_STATUS.GONE,
        );
    }
    if (err instanceof jwt.JsonWebTokenError) {
        errorMessage = ERROR_MESSAGE.UNAUTHORIZED;
        status = HTTP_STATUS.UNAUTHORIZED;
    }
    if (err.isOperational) {
        return res.error({ message: err.message }, err.statusCode);
    }
    res.error({ message: errorMessage }, status);
};

export default errorHandle;
