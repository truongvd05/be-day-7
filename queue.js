import "dotenv/config";
import queueModel from "#models/queue.model.js";
import tasks from "#tasks/index.js";
import processEmailJob from "#queues/handlers/processEmailJob.js";

setInterval(async () => {
    try {
        const pendingJobs = await queueModel.findAllPending();
        if (!pendingJobs) return;
        switch (pendingJobs.type) {
            case "sendVerifyEmail":
                console.log("sendEmail");
                await processEmailJob(pendingJobs, tasks.sendVerificationEmail);
                break;
            case "sendChangePasswordEmail":
                console.log("sendEmail");
                await processEmailJob(
                    pendingJobs,
                    tasks.sendPasswordChangeEmail,
                );
            default:
        }
    } catch (err) {
        console.error("Worker error:", err.message);
    }
}, 1000);
