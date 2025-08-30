import { Router, Request, Response } from 'express';
import { changePasswordSchema, validateBody } from '../middleware/validation.js';
import { authenticateToken, requireAuth } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import { userRegistrationSchema, userLoginSchema } from '../middleware/validation.js';
import { hashPassword, comparePassword } from '../utils/password.js';
import { generateToken, refreshToken, verifyRefreshToken } from '../utils/jwt.js';
import { createUserSecure } from '../model/model.js';
import { User } from '../model/model.js';
import { ValidationError, AuthenticationError, ConflictError } from '../utils/error.js';
import logger from '../config/logger.js';

const router = Router();

/**
 * POST /auth/register
 * Register a new user
 */
router.post('/register', 
    validateBody(userRegistrationSchema),
    asyncHandler(async (req: Request, res: Response) => {
        const { name, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email, isDeleted: false });
        if (existingUser) {
            throw new ConflictError('User with this email already exists', { email });
        }

        // Create new user
        const user = await createUserSecure(name, email, password);

        // Generate tokens
        const accessToken = generateToken({
            userId: user.id,
            email: user.email,
            roles: user.roles
        });

        const refreshTokenValue = refreshToken({
            userId: user.id,
            email: user.email,
            roles: user.roles
        });

        // Log successful registration
        logger.info('User registered successfully', {
            userId: user.id,
            email: user.email
        });

        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                roles: user.roles,
                createdAt: user.createdAt
            },
            tokens: {
                accessToken,
                refreshToken: refreshTokenValue
            }
        });
    })
);

/**
 * POST /auth/login
 * Login user
 */
router.post('/login',
    validateBody(userLoginSchema),
    asyncHandler(async (req: Request, res: Response) => {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email, isDeleted: false }).select('+passwordHash');
        if (!user) {
            throw new AuthenticationError('Invalid email or password');
        }

        // Verify password
        const isPasswordValid = await comparePassword(password, user.passwordHash);
        if (!isPasswordValid) {
            throw new AuthenticationError('Invalid email or password');
        }

        // Update last login
        user.lastLoginAt = new Date();
        await user.save();

        // Generate tokens
        const accessToken = generateToken({
            userId: user.id,
            email: user.email,
            roles: user.roles
        });

        const refreshTokenValue = refreshToken({
            userId: user.id,
            email: user.email,
            roles: user.roles
        });

        // Log successful login
        logger.info('User logged in successfully', {
            userId: user.id,
            email: user.email
        });

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                roles: user.roles,
                lastLoginAt: user.lastLoginAt
            },
            tokens: {
                accessToken,
                refreshToken: refreshTokenValue
            }
        });
    })
);

/**
 * POST /auth/refresh
 * Refresh access token using refresh token
 */
router.post('/refresh',
    asyncHandler(async (req: Request, res: Response) => {
        const { refreshToken: refreshTokenValue } = req.body;

        if (!refreshTokenValue) {
            throw new ValidationError('Refresh token is required');
        }

        try {
            // Verify refresh token
            const decoded = verifyRefreshToken(refreshTokenValue);
            
            // Check if it's a refresh token
            if (decoded.type !== 'refresh') {
                throw new AuthenticationError('Invalid token type');
            }

            // Find user
            const user = await User.findById(decoded.userId);
            if (!user || user.isDeleted) {
                throw new AuthenticationError('User not found');
            }

            // Generate new tokens
            const newAccessToken = generateToken({
                userId: user.id,
                email: user.email,
                roles: user.roles
            });

            const newRefreshToken = refreshToken({
                userId: user.id,
                email: user.email,
                roles: user.roles
            });

            // Log token refresh
            logger.info('Token refreshed successfully', {
                userId: user.id,
                email: user.email
            });

            res.json({
                message: 'Token refreshed successfully',
                tokens: {
                    accessToken: newAccessToken,
                    refreshToken: newRefreshToken
                }
            });

        } catch (error) {
            logger.error('Invalid refresh token', { error });
            throw new AuthenticationError('Invalid refresh token');
        }
    })
);

/**
 * GET /auth/me
 * Get current user profile
 */
router.get('/me',
    authenticateToken,
    requireAuth,
    asyncHandler(async (req: Request, res: Response) => {
        const user = await User.findById(req.user?.userId);
        
        if (!user || user.isDeleted) {
            throw new AuthenticationError('User not found');
        }

        res.json({
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                roles: user.roles,
                lastLoginAt: user.lastLoginAt,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            }
        });
    })
);

/**
 * POST /auth/logout
 * Logout user (client should discard tokens)
 */
router.post('/logout',
    authenticateToken,
    requireAuth,
    asyncHandler((req: Request, res: Response) => {
        // In a more advanced setup, you might want to blacklist the token
        // For now, we'll just return success and let the client discard tokens
        
        logger.info('User logged out', {
            userId: req.user?.userId,
            email: req.user?.email
        });

        res.json({
            message: 'Logout successful'
        });
    })
);

/**
 * POST /auth/change-password
 * Change user password
 */
router.post('/change-password',
    authenticateToken,
    requireAuth,
    validateBody(changePasswordSchema),
    asyncHandler(async (req: Request, res: Response) => {
        const { currentPassword, newPassword } = req.body;

        // Get user with password hash
        const user = await User.findById(req.user?.userId).select('+passwordHash');
        if (!user) {
            throw new AuthenticationError('User not found');
        }

        // Verify current password
        const isCurrentPasswordValid = await comparePassword(currentPassword, user.passwordHash);
        if (!isCurrentPasswordValid) {
            throw new AuthenticationError('Current password is incorrect');
        }

        // Hash new password
        const newPasswordHash = await hashPassword(newPassword);
        user.passwordHash = newPasswordHash;
        await user.save();

        // Log password change
        logger.info('Password changed successfully', {
            userId: user.id,
            email: user.email
        });

        res.json({
            message: 'Password changed successfully'
        });
    })
);

export default router;
