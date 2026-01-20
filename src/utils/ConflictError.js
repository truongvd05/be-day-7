import AppError from "./AppError.js";

class ConflictError extends AppError {
    constructor(message = "Email already exists") {
        super(message, 409);
    }
}

export default ConflictError;
