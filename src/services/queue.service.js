import queueModel from "#models/queue.model.js";

class QueueService {
    async push(type, payload) {
        await queueModel.create(type, payload);
    }
}

export default new QueueService();
