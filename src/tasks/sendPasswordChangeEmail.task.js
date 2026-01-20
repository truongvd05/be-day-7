import transporter from "#config/nodemailer.js";

const sendPasswordChangeEmail = async (user) => {
    const toEmail =
        process.env.NODE_ENV === "development" &&
        process.env.EMAIL_TO &&
        process.env.EMAIL_TO.trim()
            ? process.env.EMAIL_TO
            : user.email;
    const time = new Date().toLocaleString("vi-VN");
    const mailOptions = {
        from: process.env.EMAIL_FROM || "<thanh090800@gmail.com>",
        to: toEmail,
        subject: "Đổi mật khẩu",
        html: `
            <h3>Xin chào ${user.name || ""}</h3>
            <p>Mật khẩu của bạn đã được đổi lúc <b>${time}</b> nếu bạn là người đổi mật khẩu hãy bỏ qua email này</p>
        `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("Change Password Message sent: %s", info.messageId);
};

export default sendPasswordChangeEmail;
