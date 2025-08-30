import { ZodError } from 'zod';
import jwt from 'jsonwebtoken';
import { ValidationError, AuthenticationError, AuthorizationError, NotFoundError, ConflictError, RateLimitError, InternalServerError, BadRequestError } from '../utils/error.js';
import logger from '../config/logger.js';
import env from '../config/env.js';
/**
 * Sanitize error message for production
 * @param error - The error object
 * @returns Sanitized error message
 */
function sanitizeErrorMessage(error) {
    if (env.NODE_ENV === 'production') {
        // In production, don't expose internal error details
        if (error instanceof ZodError) {
            return 'Validation failed';
        }
        if (error instanceof jwt.JsonWebTokenError) {
            return 'Invalid token';
        }
        if (error instanceof jwt.TokenExpiredError) {
            return 'Token expired';
        }
        if (error instanceof InternalServerError) {
            return 'Internal server error';
        }
        // For known errors, use their message
        if (error instanceof ValidationError ||
            error instanceof AuthenticationError ||
            error instanceof AuthorizationError ||
            error instanceof NotFoundError ||
            error instanceof ConflictError ||
            error instanceof RateLimitError ||
            error instanceof BadRequestError) {
            return error.message;
        }
        // For unknown errors, use generic message
        return 'Something went wrong';
    }
    // In development, return full error message
    return error.message;
}
/**
 * Get error status code based on error type
 * @param error - The error object
 * @returns HTTP status code
 */
function getErrorStatusCode(error) {
    if (error instanceof ValidationError)
        return 400;
    if (error instanceof AuthenticationError)
        return 401;
    if (error instanceof AuthorizationError)
        return 403;
    if (error instanceof NotFoundError)
        return 404;
    if (error instanceof ConflictError)
        return 409;
    if (error instanceof RateLimitError)
        return 429;
    if (error instanceof BadRequestError)
        return 400;
    if (error instanceof ZodError)
        return 400;
    if (error instanceof jwt.JsonWebTokenError)
        return 401;
    if (error instanceof jwt.TokenExpiredError)
        return 401;
    return 500;
}
/**
 * Get error code for client handling
 * @param error - The error object
 * @returns Error code string
 */
function getErrorCode(error) {
    if (error instanceof ValidationError)
        return 'VALIDATION_ERROR';
    if (error instanceof AuthenticationError)
        return 'AUTHENTICATION_ERROR';
    if (error instanceof AuthorizationError)
        return 'AUTHORIZATION_ERROR';
    if (error instanceof NotFoundError)
        return 'NOT_FOUND_ERROR';
    if (error instanceof ConflictError)
        return 'CONFLICT_ERROR';
    if (error instanceof RateLimitError)
        return 'RATE_LIMIT_ERROR';
    if (error instanceof BadRequestError)
        return 'BAD_REQUEST_ERROR';
    if (error instanceof ZodError)
        return 'VALIDATION_ERROR';
    if (error instanceof jwt.JsonWebTokenError)
        return 'INVALID_TOKEN';
    if (error instanceof jwt.TokenExpiredError)
        return 'TOKEN_EXPIRED';
    return 'INTERNAL_SERVER_ERROR';
}
/**
 * Format error details for response
 * @param error - The error object
 * @returns Formatted error details
 */
function formatErrorDetails(error) {
    if (error instanceof ZodError) {
        return {
            errors: error.errors.map(err => ({
                field: err.path.join('.'),
                message: err.message,
                code: err.code
            }))
        };
    }
    if (error instanceof ValidationError ||
        error instanceof AuthenticationError ||
        error instanceof AuthorizationError ||
        error instanceof NotFoundError ||
        error instanceof ConflictError ||
        error instanceof RateLimitError ||
        error instanceof BadRequestError) {
        return error.details;
    }
    return undefined;
}
/**
 * Log error with appropriate level
 * @param error - The error object
 * @param req - Express request object
 * @param statusCode - HTTP status code
 */
function logError(error, req, statusCode) {
    const logData = {
        error: error.message,
        stack: error.stack,
        statusCode,
        method: req.method,
        path: req.path,
        query: req.query,
        body: req.body,
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        userId: req.user?.userId,
        requestId: req.headers['x-request-id']
    };
    // Log at appropriate level based on status code
    if (statusCode >= 500) {
        logger.error('Server error:', logData);
    }
    else if (statusCode >= 400) {
        logger.warn('Client error:', logData);
    }
    else {
        logger.info('Other error:', logData);
    }
}
/**
 * Global error handling middleware
 * Handles all types of errors and formats them consistently
 */
export function errorHandler(error, req, res) {
    const statusCode = getErrorStatusCode(error);
    const message = sanitizeErrorMessage(error);
    const code = getErrorCode(error);
    const details = formatErrorDetails(error);
    // Log the error
    logError(error, req, statusCode);
    // Create error response
    const errorResponse = {
        message,
        statusCode,
        code,
        details,
        timestamp: new Date().toISOString(),
        path: req.path,
        method: req.method,
        requestId: req.headers['x-request-id']
    };
    // Send error response
    res.status(statusCode).json(errorResponse);
}
/**
 * 404 Not Found handler
 * Handles requests to non-existent routes
 */
export function notFoundHandler(req, res, next) {
    const error = new NotFoundError(`Route ${req.method} ${req.path} not found`);
    logger.warn('Route not found:', {
        method: req.method,
        path: req.path,
        userAgent: req.get('User-Agent'),
        ip: req.ip
    });
    next(error);
}
/**
 * Async error wrapper
 * Wraps async route handlers to catch unhandled promise rejections
 * @param fn - Async function to wrap
 * @returns Wrapped function that handles errors
 */
export function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}
/**
 * Request validation error handler
 * Specifically handles validation errors from middleware
 */
export function validationErrorHandler(error, req, res, next) {
    if (error instanceof ZodError) {
        const validationError = new ValidationError('Validation failed', {
            errors: error.errors.map(err => ({
                field: err.path.join('.'),
                message: err.message,
                code: err.code
            }))
        });
        next(validationError);
        return;
    }
    next(error);
}
/**
 * JWT error handler
 * Specifically handles JWT-related errors
 */
export function jwtErrorHandler(error, req, res, next) {
    if (error instanceof jwt.JsonWebTokenError) {
        const authError = new AuthenticationError('Invalid token');
        next(authError);
        return;
    }
    if (error instanceof jwt.TokenExpiredError) {
        const authError = new AuthenticationError('Token expired');
        next(authError);
        return;
    }
    next(error);
}
/**
 * Database error handler
 * Handles MongoDB/Mongoose errors
 */
export function databaseErrorHandler(error, req, res, next) {
    // Handle MongoDB duplicate key errors
    if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        const conflictError = new ConflictError(`${field} already exists`);
        next(conflictError);
        return;
    }
    // Handle MongoDB validation errors
    if (error.name === 'ValidationError') {
        const validationError = new ValidationError('Database validation failed', {
            errors: Object.values(error.errors).map((err) => ({
                field: err.path,
                message: err.message
            }))
        });
        next(validationError);
        return;
    }
    // Handle MongoDB cast errors (invalid ObjectId)
    if (error.name === 'CastError') {
        const badRequestError = new BadRequestError('Invalid ID format');
        next(badRequestError);
        return;
    }
    next(error);
}
/**
 * Request timeout handler
 * Handles requests that take too long
 */
export function timeoutHandler(timeoutMs = 30000) {
    return (req, res, next) => {
        const timeout = setTimeout(() => {
            if (!res.headersSent) {
                const timeoutError = new Error('Request timeout');
                next(timeoutError);
            }
        }, timeoutMs);
        res.on('finish', () => {
            clearTimeout(timeout);
        });
        next();
    };
}
