import "dotenv/config";
import jwtconfig from "#config/jwt.js";
import queueModel from "#models/queue.model.js";
import jwt from "jsonwebtoken";
import userModel from "#models/user.model.js";
import { QUEUE_STATUS } from "#config/constants.js";
import emailService from "#services/email.service.js";

setInterval(async () => {
    const pendingJobs = await queueModel.findAllPending();
    if (!pendingJobs) return;
    switch (pendingJobs.type) {
        case "sendVerifyEmail":
            console.log("sendEmail");
            try {
                await queueModel.updateStatus(
                    pendingJobs.id,
                    QUEUE_STATUS.INPROGRESS,
                );
                const payload = JSON.parse(pendingJobs.payload);
                const decoded = jwt.verify(
                    payload.token,
                    jwtconfig.emailSecret,
                );
                const user = await userModel.findUserById(decoded.sub);
                if (!user) throw new Error("User not found");
                await emailService.sendVerifyEmail(user.email, payload.token);
                await queueModel.updateStatus(
                    pendingJobs.id,
                    QUEUE_STATUS.COMPLETED,
                );
            } catch (err) {
                await queueModel.updateStatus(
                    pendingJobs.id,
                    QUEUE_STATUS.FAILED,
                );
            }
            break;
        default:
    }
}, 1000);
