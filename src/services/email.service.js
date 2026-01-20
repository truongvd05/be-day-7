import transporter from "#config/nodemailer.js";

class EmailService {
    async sendVerifyEmail(email, token) {
        const url = process.env.FRONTEND_URL || "http://localhost:5173";
        const verifyUrl = `${url}/#/verify-email?token=${token}`;
        const toEmail =
            process.env.NODE_ENV === "development" &&
            process.env.EMAIL_TO &&
            process.env.EMAIL_TO.trim()
                ? process.env.EMAIL_TO
                : email;
        const info = await transporter.sendMail({
            from: process.env.EMAIL_FROM || "<thanh090800@gmail.com>",
            to: toEmail,
            subject: "Xác thực email của bạn",
            html: `<p>Click vào đây để verify email <a href="${verifyUrl}" target="_blank">here</a></p>`,
        });

        console.log("Message sent: %s", info.messageId);
    }
}

export default new EmailService();
