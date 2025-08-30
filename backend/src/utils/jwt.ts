import jwt, { SignOptions } from 'jsonwebtoken';
import env from '../config/env.js';


const JWT_SECRET = env.JWT_SECRET;
const JWT_EXPIRES_IN = Number(env.JWT_EXPIRES_IN);
const JWT_REFRESH_SECRET = env.JWT_REFRESH_SECRET;
const JWT_REFRESH_EXPIRES_IN = Number(env.JWT_REFRESH_EXPIRES_IN);
const JWT_ALGORITHM = env.JWT_ALGORITHM;

export interface TokenPayload {
    type: string;
    userId: string;
    email: string;
    roles: string[];
}



const generateToken = (payload: object) : string => {
    const options : SignOptions = {
        expiresIn: JWT_EXPIRES_IN,
        algorithm: JWT_ALGORITHM
    }
    return jwt.sign(payload, JWT_SECRET, options);
}

const verifyToken = (token: string) : TokenPayload => {
    return jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] }) as TokenPayload;
}   

const refreshToken = (payload: object) : string => {
    const options : SignOptions = {
        expiresIn: JWT_REFRESH_EXPIRES_IN,
        algorithm: JWT_ALGORITHM
    }
    return jwt.sign(payload, JWT_REFRESH_SECRET, options);
}

const verifyRefreshToken = (token: string) : TokenPayload => {
    return jwt.verify(token, JWT_REFRESH_SECRET, { algorithms: [JWT_ALGORITHM] }) as TokenPayload;
}

const extractTokenFromHeader = (header: string) : string | null => {
    const [type, token] = header.split(' ');
    return type === 'Bearer' ? token : null;
}   

export { generateToken, verifyToken, refreshToken, extractTokenFromHeader, verifyRefreshToken };