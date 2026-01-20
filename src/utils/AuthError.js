import AppError from "./AppError.js";
import { ERROR_MESSAGE, HTTP_STATUS } from "#config/constants.js";

class AuthError extends AppError {
    constructor(message = ERROR_MESSAGE.UNAUTHORIZED) {
        super(message, HTTP_STATUS.UNAUTHORIZED);
    }
}

export default AuthError;
