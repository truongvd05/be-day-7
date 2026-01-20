import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.MAIL_AUTH_USER,
        pass: process.env.MAIL_AUTH_PASS,
    },
});

export default transporter;
