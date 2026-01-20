import pool from "#config/database.js";

const create = async ({ jti, user_id, expired_at }) => {
    const [rows] = await pool.query(
        `INSERT INTO revoked_tokens (jti, user_id, expired_at) VALUES (?, ?, ?)`,
        [jti, user_id, expired_at],
    );
    return rows;
};

const existsByJti = async (jti) => {
    const [rows] = await pool.query(
        `SELECT 1 FROM revoked_tokens WHERE jti = ? LIMIT 1`,
        [jti],
    );
    return rows.length > 0;
};

const revokeAllByUser = async (id) => {
    const [rows] = await pool.query(
        `DELETE FROM revoked_tokens WHERE user_id = ?`,
        [id],
    );
    return rows.affectedRows;
};

export default { create, existsByJti, revokeAllByUser };
