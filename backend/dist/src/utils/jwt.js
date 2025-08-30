import jwt from 'jsonwebtoken';
import env from '../config/env.js';
const JWT_SECRET = env.JWT_SECRET;
const JWT_EXPIRES_IN = Number(env.JWT_EXPIRES_IN);
const JWT_REFRESH_SECRET = env.JWT_REFRESH_SECRET;
const JWT_REFRESH_EXPIRES_IN = Number(env.JWT_REFRESH_EXPIRES_IN);
const JWT_ALGORITHM = env.JWT_ALGORITHM;
const generateToken = (payload) => {
    const options = {
        expiresIn: JWT_EXPIRES_IN,
        algorithm: JWT_ALGORITHM
    };
    return jwt.sign(payload, JWT_SECRET, options);
};
const verifyToken = (token) => {
    return jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
};
const refreshToken = (payload) => {
    const options = {
        expiresIn: JWT_REFRESH_EXPIRES_IN,
        algorithm: JWT_ALGORITHM
    };
    return jwt.sign(payload, JWT_REFRESH_SECRET, options);
};
const verifyRefreshToken = (token) => {
    return jwt.verify(token, JWT_REFRESH_SECRET, { algorithms: [JWT_ALGORITHM] });
};
const extractTokenFromHeader = (header) => {
    const [type, token] = header.split(' ');
    return type === 'Bearer' ? token : null;
};
export { generateToken, verifyToken, refreshToken, extractTokenFromHeader, verifyRefreshToken };
