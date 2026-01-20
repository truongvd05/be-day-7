import jwtService from "#services/jwtService.js";
import jwtconfig from "#config/jwt.js";
import transporter from "#config/nodemailer.js";

const sendVerificationEmail = async (user) => {
    const token = jwtService(
        user.id,
        jwtconfig.emailSecret,
        jwtconfig.emailTokenTTL,
    );
    const toEmail =
        process.env.NODE_ENV === "development" &&
        process.env.EMAIL_TO &&
        process.env.EMAIL_TO.trim()
            ? process.env.EMAIL_TO
            : email;

    const url = process.env.FRONTEND_URL || "http://localhost:5173";
    const verifyUrl = `${url}/#/verify-email?token=${token}`;

    const mailOptions = {
        from: process.env.EMAIL_FROM || "<thanh090800@gmail.com>",
        to: toEmail,
        subject: "Xác thực email",
        html: `
            <h3>Xin chào ${user.name || ""}</h3>
            <p>Vui lòng click vào link bên dưới để xác thực email:</p>
            <a href="${verifyUrl}">${verifyUrl}</a>
            <p>Link sẽ hết hạn sau 2h.</p>
        `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("Verifi Message sent: %s", info.messageId);
};

export default sendVerificationEmail;
