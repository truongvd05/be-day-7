import pool from "#config/database.js";
import AuthError from "#utils/AuthError.js";
import ConflictError from "#utils/ConflictError.js";
import bcrypt from "bcrypt";

const findUserByEmail = async (email) => {
    const [rows] = await pool.query(
        `SELECT id, email, password, verified_at  FROM users WHERE email = ? LIMIT 1`,
        [email],
    );
    return rows[0];
};

const registerUser = async (email, password) => {
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const [rows] = await pool.query(
            `INSERT INTO users (email, password) VALUES (?, ?)`,
            [email, hashedPassword],
        );
        return rows;
    } catch (err) {
        throw new ConflictError("Email already exists");
    }
};

const findUserById = async (id) => {
    const [rows] = await pool.query(
        `SELECT id, email, verified_at FROM users WHERE id = ?`,
        [id],
    );
    return rows[0] || null;
};

const updateRefreshToken = async (id, token, ttl) => {
    const [rows] = await pool.query(
        `update users set refresh_token = ?, refresh_expires_at = ? where id = ?`,
        [token, ttl, id],
    );
    return rows.affectedRows;
};

const getRefreshToken = async (refreshToken) => {
    const [rows] = await pool.query(
        `select * from users where refresh_token = ? and refresh_expires_at >= now()`,
        [refreshToken],
    );
    return rows[0] ?? null;
};

const findUserByRefreshToken = async (refreshToken) => {
    const [rows] = await pool.query(
        `select * from users where refresh_token = ?`,
        [refreshToken],
    );
    return rows[0] ?? null;
};

const verifyEmail = async (id) => {
    const [rows] = await pool.query(
        `UPDATE users SET verified_at = NOW() WHERE id = ? AND verified_at IS NULL`,
        [id],
    );
    if (rows.affectedRows === 0) {
        throw new AuthError("Email already verified");
    }

    return true;
};

export default {
    findUserByEmail,
    registerUser,
    findUserById,
    updateRefreshToken,
    getRefreshToken,
    findUserByRefreshToken,
    verifyEmail,
};
