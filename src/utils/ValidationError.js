import AppError from "./AppError.js";
import { ERROR_MESSAGE, HTTP_STATUS } from "#config/constants.js";

class ValidationError extends AppError {
    constructor(message = ERROR_MESSAGE.VALIDATE) {
        super(message, HTTP_STATUS.BAD_REQUEST);
    }
}

export default ValidationError;
