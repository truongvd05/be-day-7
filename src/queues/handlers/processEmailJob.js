import "dotenv/config";
import queueModel from "#models/queue.model.js";
import { QUEUE_STATUS } from "#config/constants.js";
import jwtconfig from "#config/jwt.js";
import jwt from "jsonwebtoken";
import userModel from "#models/user.model.js";

const processEmailJob = async (job, handler) => {
    const SECRET_MAP = {
        email: jwtconfig.emailSecret,
        password: jwtconfig.changePasswordSecret,
    };
    try {
        await queueModel.updateStatus(job.id, QUEUE_STATUS.INPROGRESS);
        const payload = JSON.parse(job.payload);
        const secret = SECRET_MAP[payload.secretType];
        if (!secret) {
            throw new Error("Invalid secret type");
        }
        console.log(secret);

        const decoded = jwt.verify(payload.token, secret);
        const user = await userModel.findUserById(decoded.sub);
        if (!user) throw new Error("User not found");
        await handler(user);
        await queueModel.updateStatus(job.id, QUEUE_STATUS.COMPLETED);
    } catch (err) {
        console.log(err);

        await queueModel.updateStatus(job.id, QUEUE_STATUS.FAILED);
        throw err;
    }
};

export default processEmailJob;
