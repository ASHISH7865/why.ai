import { verifyToken, extractTokenFromHeader } from '../utils/jwt.js';
import { AuthenticationError, AuthorizationError } from '../utils/error.js';
import logger from '../config/logger.js';
/**
 * Extract token from cookies
 */
function extractTokenCookie(cookies) {
    return cookies?.accessToken ?? null;
}
/**
 * Middleware to authenticate JWT token
 * Adds user data to req.user if token is valid
 * Does not block the request if token is missing/invalid
 */
export function authenticateToken(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader
            ? extractTokenFromHeader(authHeader)
            : extractTokenCookie(req.cookies);
        if (!token) {
            // No token provided, continue without authentication
            next();
            return;
        }
        // Verify the token
        const decoded = verifyToken(token);
        // Check if it's an access token
        if (decoded.type !== 'access') {
            throw new AuthenticationError('Invalid token type');
        }
        // Add user data to request
        req.user = {
            userId: decoded.userId,
            email: decoded.email,
            roles: decoded.roles
        };
        next();
    }
    catch (error) {
        // Token verification failed, continue without authentication
        // Don't throw error here as this middleware is optional
        logger.debug('Token verification failed:', error instanceof Error ? error.message : 'Unknown error');
        next();
    }
}
/**
 * Middleware to require authentication
 * Blocks the request if no valid token is provided
 */
export function requireAuth(req, res, next) {
    try {
        if (!req.user) {
            throw new AuthenticationError('Authentication required');
        }
        next();
    }
    catch (error) {
        next(error);
    }
}
/**
 * Middleware to require specific roles
 * @param roles - Array of required roles
 * @returns Express middleware function
 */
export function requireRole(roles) {
    return (req, res, next) => {
        try {
            if (!req.user) {
                throw new AuthenticationError('Authentication required');
            }
            // Check if user has any of the required roles
            const hasRequiredRole = req.user.roles.some(role => roles.includes(role));
            if (!hasRequiredRole) {
                throw new AuthorizationError(`Access denied. Required roles: ${roles.join(', ')}`);
            }
            next();
        }
        catch (error) {
            next(error);
        }
    };
}
/**
 * Middleware to require admin role
 */
export function requireAdmin(req, res, next) {
    requireRole(['admin'])(req, res, next);
}
/**
 * Middleware to require user role (any authenticated user)
 */
export function requireUser(req, res, next) {
    requireRole(['user', 'admin'])(req, res, next);
}
/**
 * Optional authentication middleware
 * Sets req.user if token is valid, but doesn't block if invalid
 */
export function optionalAuth(req, res, next) {
    authenticateToken(req, res, next);
}
/**
 * Middleware to check if user owns the resource
 * @param resourceUserId - The user ID of the resource owner
 * @returns Express middleware function
 */
export function requireOwnership(resourceUserId) {
    return (req, res, next) => {
        try {
            if (!req.user) {
                throw new AuthenticationError('Authentication required');
            }
            // Admin can access any resource
            if (req.user.roles.includes('admin')) {
                next();
                return;
            }
            // Check if user owns the resource
            if (req.user.userId !== resourceUserId) {
                throw new AuthorizationError('Access denied. You can only access your own resources.');
            }
            next();
        }
        catch (error) {
            next(error);
        }
    };
}
/**
 * Middleware to check if user can access topic
 * @param topicVisibility - The visibility of the topic
 * @param topicUserId - The user ID of the topic owner
 * @returns Express middleware function
 */
export function requireTopicAccess(topicVisibility, topicUserId) {
    return (req, res, next) => {
        try {
            // Public topics are accessible to everyone
            if (topicVisibility === 'public') {
                next();
                return;
            }
            // Private topics require authentication
            if (!req.user) {
                throw new AuthenticationError('Authentication required to access this topic');
            }
            // Admin can access any topic
            if (req.user.roles.includes('admin')) {
                next();
                return;
            }
            // Topic owner can access their own topics
            if (req.user.userId === topicUserId) {
                next();
                return;
            }
            // Unlisted topics are accessible to authenticated users
            if (topicVisibility === 'unlisted') {
                next();
                return;
            }
            throw new AuthorizationError('Access denied to this topic');
        }
        catch (error) {
            next(error);
        }
    };
}
