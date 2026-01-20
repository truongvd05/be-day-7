import ValidationError from "./ValidationError.js";

const validateChangePassword = ({ password, newPassword, comfirmPassword }) => {
    if (![password, newPassword, comfirmPassword].every(Boolean)) {
        throw new ValidationError("Missing password fields");
    }

    if (newPassword.length < 6) {
        throw new ValidationError("Mật khẩu phải ít nhất 6 ký tự");
    }

    if (newPassword !== comfirmPassword) {
        throw new ValidationError("Mật khẩu mới phải giống nhau");
    }
};

export default validateChangePassword;
