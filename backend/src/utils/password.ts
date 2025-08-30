import bcrypt from 'bcryptjs';
import env from '../config/env.js';

const SALT_ROUNDS = env.BCRYPT_SALT_ROUNDS;

// Validate environment configuration
if (!SALT_ROUNDS || SALT_ROUNDS < 10 || SALT_ROUNDS > 14) {
    throw new Error('BCRYPT_SALT_ROUNDS must be between 10 and 14');
}

/**
 * Validates password strength requirements
 * @param password - The password to validate
 * @throws {Error} - If password doesn't meet requirements
 */
const validatePassword = (password: string): void => {
    if (!password || typeof password !== 'string') {
        throw new Error('Password must be a non-empty string');
    }
    
    if (password.length < 8) {
        throw new Error('Password must be at least 8 characters long');
    }
    
    // Add more validation as needed (uppercase, lowercase, numbers, symbols)
};

/**
 * Hashes a password using bcrypt with configurable salt rounds
 * @param password - The plain text password to hash
 * @returns Promise<string> - The hashed password
 * @throws {Error} - If password is invalid or hashing fails
 */
const hashPassword = async (password: string): Promise<string> => {
    try {
        validatePassword(password);
        
        const salt = await bcrypt.genSalt(SALT_ROUNDS);
        const hashedPassword = await bcrypt.hash(password, salt);
        return hashedPassword;
    } catch (error) {
        throw new Error(`Password hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
};

/**
 * Compares a plain text password with a hashed password
 * @param password - The plain text password to verify
 * @param hashedPassword - The hashed password to compare against
 * @returns Promise<boolean> - True if passwords match, false otherwise
 * @throws {Error} - If comparison fails
 */
const comparePassword = async (password: string, hashedPassword: string): Promise<boolean> => {
    try {
        if (!password || !hashedPassword) {
            return false;
        }
        
        return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
        throw new Error(`Password comparison failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
};

export { hashPassword, comparePassword, validatePassword };