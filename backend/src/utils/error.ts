/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Standard error response interface for API consistency
 */
export interface ErrorResponse {
    message: string;
    statusCode: number;
    code: string;
    details?: any;
    timestamp: string;
}

/**
 * Base error class with common properties
 */
abstract class BaseError extends Error {
    public readonly statusCode: number;
    public readonly code: string;
    public readonly details?: any;

    constructor(message: string, statusCode: number, code: string, details?: any) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.details = details;
        this.name = this.constructor.name;
    }

    serialize(): ErrorResponse {
        return {
            message: this.message,
            statusCode: this.statusCode,
            code: this.code,
            details: this.details,
            timestamp: new Date().toISOString()
        };
    }
}

/**
 * Error thrown when input validation fails
 * @extends BaseError
 */
export class ValidationError extends BaseError {
    constructor(message: string, details?: any) {
        super(message, 400, 'VALIDATION_ERROR', details);
    }
}

/**
 * Error thrown when authentication fails
 * @extends BaseError
 */
export class AuthenticationError extends BaseError {
    constructor(message = 'Authentication failed', details?: any) {
        super(message, 401, 'AUTHENTICATION_ERROR', details);
    }
}

/**
 * Error thrown when user lacks required permissions
 * @extends BaseError
 */
export class AuthorizationError extends BaseError {
    constructor(message = 'Access denied', details?: any) {
        super(message, 403, 'AUTHORIZATION_ERROR', details);
    }
}

/**
 * Error thrown when requested resource is not found
 * @extends BaseError
 */
export class NotFoundError extends BaseError {
    constructor(message = 'Resource not found', details?: any) {
        super(message, 404, 'NOT_FOUND_ERROR', details);
    }
}

/**
 * Error thrown when resource conflicts with existing data
 * @extends BaseError
 */
export class ConflictError extends BaseError {
    constructor(message = 'Resource conflict', details?: any) {
        super(message, 409, 'CONFLICT_ERROR', details);
    }
}

/**
 * Error thrown when rate limit is exceeded
 * @extends BaseError
 */
export class RateLimitError extends BaseError {
    constructor(message = 'Rate limit exceeded', details?: any) {
        super(message, 429, 'RATE_LIMIT_ERROR', details);
    }
}

/**
 * Error thrown for bad requests
 * @extends BaseError
 */
export class BadRequestError extends BaseError {
    constructor(message = 'Bad request', details?: any) {
        super(message, 400, 'BAD_REQUEST_ERROR', details);
    }
}

/**
 * Error thrown for internal server errors
 * @extends BaseError
 */
export class InternalServerError extends BaseError {
    constructor(message = 'Internal server error', details?: any) {
        super(message, 500, 'INTERNAL_SERVER_ERROR', details);
    }
}

/**
 * Error thrown when service is unavailable
 * @extends BaseError
 */
export class ServiceUnavailableError extends BaseError {
    constructor(message = 'Service unavailable', details?: any) {
        super(message, 503, 'SERVICE_UNAVAILABLE_ERROR', details);
    }
}

/**
 * Error thrown when feature is not implemented
 * @extends BaseError
 */
export class NotImplementedError extends BaseError {
    constructor(message = 'Not implemented', details?: any) {
        super(message, 501, 'NOT_IMPLEMENTED_ERROR', details);
    }
}

/**
 * Error thrown for bad gateway errors
 * @extends BaseError
 */
export class BadGatewayError extends BaseError {
    constructor(message = 'Bad gateway', details?: any) {
        super(message, 502, 'BAD_GATEWAY_ERROR', details);
    }
}

/**
 * Error thrown for gateway timeout errors
 * @extends BaseError
 */
export class GatewayTimeoutError extends BaseError {
    constructor(message = 'Gateway timeout', details?: any) {
        super(message, 504, 'GATEWAY_TIMEOUT_ERROR', details);
    }
}