import { Request, Response, NextFunction } from 'express';
import redisClient from '../config/redis.js';
import { RateLimitError } from '../utils/error.js';
import logger from '../config/logger.js';
import env from '../config/env.js';

interface RateLimitConfig {
    windowMs: number;
    maxRequests: number;
    keyGenerator?: (req: Request) => string;
    skipSuccessfulRequests?: boolean;
    skipFailedRequests?: boolean;
    message?: string;
}

interface RateLimitInfo {
    limit: number;
    remaining: number;
    reset: number;
    retryAfter: number;
}

/**
 * Default key generator for rate limiting
 * Uses IP address or user ID if authenticated
 */
function defaultKeyGenerator(req: Request): string {
    // Use user ID if authenticated, otherwise use IP
    if (req.user?.userId) {
        return `rate_limit:user:${req.user.userId}`;
    }
    
    // Use IP address for anonymous users
    const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
    return `rate_limit:ip:${ip}`;
}

/**
 * Get rate limit information from Redis
 */
async function getRateLimitInfo(key: string, limit: number, windowMs: number): Promise<RateLimitInfo> {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get all requests in the current window
    const requests = await redisClient.zRangeByScore(key, windowStart, '+inf');
    
    // Remove expired entries
    await redisClient.zRemRangeByScore(key, '-inf', windowStart - 1);
    
    // Add current request
    await redisClient.zAdd(key, { score: now, value: now.toString() });
    
    // Set expiration for the key
    await redisClient.expire(key, Math.ceil(windowMs / 1000));
    
    const currentCount = requests.length + 1;
    const remaining = Math.max(0, limit - currentCount);
    const reset = now + windowMs;
    const retryAfter = remaining === 0 ? Math.ceil(windowMs / 1000) : 0;
    
    return {
        limit,
        remaining,
        reset,
        retryAfter
    };
}

/**
 * Rate limiting middleware using Redis
 * @param config - Rate limiting configuration
 * @returns Express middleware function
 */
export function rateLimit(config: RateLimitConfig) {
    const {
        windowMs = env.RATE_LIMIT_WINDOW_MS,
        maxRequests = env.RATE_LIMIT_MAX_REQUESTS,
        keyGenerator = defaultKeyGenerator,
        skipSuccessfulRequests = false,
        skipFailedRequests = false,
        message = 'Rate limit exceeded'
    } = config;

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
            const key = keyGenerator(req);
            const rateLimitInfo = await getRateLimitInfo(key, maxRequests, windowMs);

            // Add rate limit headers
            res.set({
                'X-RateLimit-Limit': rateLimitInfo.limit.toString(),
                'X-RateLimit-Remaining': rateLimitInfo.remaining.toString(),
                'X-RateLimit-Reset': rateLimitInfo.reset.toString()
            });

            // Check if rate limit exceeded
            if (rateLimitInfo.remaining < 0) {
                res.set('Retry-After', rateLimitInfo.retryAfter.toString());
                
                const error = new RateLimitError(message, {
                    retryAfter: rateLimitInfo.retryAfter,
                    limit: rateLimitInfo.limit,
                    reset: rateLimitInfo.reset
                });

                // Add request ID for better debugging
                logger.warn('Rate limit exceeded', {
                    requestId: req.headers['x-request-id'],
                    key,
                    limit: rateLimitInfo.limit,
                    retryAfter: rateLimitInfo.retryAfter,
                    userAgent: req.get('User-Agent'),
                    ip: req.ip
                });

                res.status(429).json(error.serialize());
                return;
            }

            // Track successful/failed requests if needed
            if (skipSuccessfulRequests || skipFailedRequests) {
                const originalSend = res.send;
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                res.send = function(body: any) {
                    const isSuccess = res.statusCode < 400;
                    
                    if ((isSuccess && skipSuccessfulRequests) || (!isSuccess && skipFailedRequests)) {
                        // Remove the current request from rate limit count
                        redisClient.zRem(key, Date.now().toString()).catch((error: unknown) => {
                            logger.error('Error removing request from rate limit:', error);
                        });
                    }
                    
                    return originalSend.call(this, body);
                };
            }

            next();
        } catch (error) {
            logger.error('Rate limiting error:', error);
            // Continue without rate limiting if Redis fails
            next();
        }
    };
}

/**
 * Strict rate limiting for authentication endpoints
 */
export function authRateLimit() {
    return rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 5, // 5 attempts per 15 minutes
        message: 'Too many authentication attempts. Please try again later.',
        skipSuccessfulRequests: true // Don't count successful logins
    });
}

/**
 * General API rate limiting
 */
export function apiRateLimit() {
    return rateLimit({
        windowMs: env.RATE_LIMIT_WINDOW_MS,
        maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
        message: 'Too many requests. Please try again later.'
    });
}

/**
 * Strict rate limiting for AI endpoints (expensive operations)
 */
export function aiRateLimit() {
    return rateLimit({
        windowMs: 60 * 1000, // 1 minute
        maxRequests: 10, // 10 requests per minute
        message: 'AI request rate limit exceeded. Please wait before making more requests.'
    });
}

/**
 * Rate limiting for user-specific operations
 */
export function userRateLimit() {
    return rateLimit({
        windowMs: 60 * 1000, // 1 minute
        maxRequests: 30, // 30 requests per minute
        keyGenerator: (req: Request) => {
            if (!req.user?.userId) {
                throw new Error('User authentication required for user rate limiting');
            }
            return `rate_limit:user:${req.user.userId}`;
        },
        message: 'User rate limit exceeded. Please wait before making more requests.'
    });
}

/**
 * Rate limiting for topic creation (prevent spam)
 */
export function topicCreationRateLimit() {
    return rateLimit({
        windowMs: 60 * 60 * 1000, // 1 hour
        maxRequests: 10, // 10 topics per hour
        keyGenerator: (req: Request) => {
            if (!req.user?.userId) {
                throw new Error('User authentication required for topic creation rate limiting');
            }
            return `rate_limit:topic_creation:${req.user.userId}`;
        },
        message: 'Topic creation rate limit exceeded. Please wait before creating more topics.'
    });
}

/**
 * Rate limiting for message creation (prevent spam)
 */
export function messageCreationRateLimit() {
    return rateLimit({
        windowMs: 60 * 1000, // 1 minute
        maxRequests: 20, // 20 messages per minute
        keyGenerator: (req: Request) => {
            if (!req.user?.userId) {
                throw new Error('User authentication required for message creation rate limiting');
            }
            return `rate_limit:message_creation:${req.user.userId}`;
        },
        message: 'Message creation rate limit exceeded. Please wait before sending more messages.'
    });
}

/**
 * Get current rate limit status for a user
 */
export async function getRateLimitStatus(req: Request): Promise<RateLimitInfo | null> {
    try {
        const key = defaultKeyGenerator(req);
        const limit = env.RATE_LIMIT_MAX_REQUESTS;
        const windowMs = env.RATE_LIMIT_WINDOW_MS;
        
        return await getRateLimitInfo(key, limit, windowMs);
    } catch (error) {
        logger.error('Error getting rate limit status:', error);
        return null;
    }
}

/**
 * Get rate limit status for all endpoints
 */
export async function getAllRateLimitStatus(req: Request): Promise<Record<string, RateLimitInfo>> {
    const status: Record<string, RateLimitInfo> = {};
    
    try {
        // Check different rate limit keys
        const keys = [
            defaultKeyGenerator(req),
            `rate_limit:topic_creation:${req.user?.userId ?? 'anonymous'}`,
            `rate_limit:message_creation:${req.user?.userId ?? 'anonymous'}`
        ];
        
        for (const key of keys) {
            const info = await getRateLimitInfo(key, 100, 15 * 60 * 1000);
            status[key] = info;
        }
        
        return status;
    } catch (error) {
        logger.error('Error getting all rate limit status:', error);
        return {};
    }
}
