import pool from "#config/database.js";

const create = async (type, payload) => {
    const [rows] = await pool.query(
        `INSERT into queues (type, payload) value (?,?)`,
        [type, JSON.stringify(payload)],
    );
    return rows;
};

const findAllPending = async () => {
    const [rows] = await pool.query(
        `select * from queues where status = "pending" limit 1`,
    );
    return rows[0];
};

const updateStatus = async (id, status) => {
    const [rows] = await pool.query(
        `update queues set status = ? where id = ?`,
        [status, id],
    );
    return rows;
};

export default { create, findAllPending, updateStatus };
