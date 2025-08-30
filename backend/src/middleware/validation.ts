import { Request, Response, NextFunction } from 'express';
import { z, ZodSchema, ZodError } from 'zod';
import { ValidationError } from '../utils/error.js';

// ===== VALIDATION MIDDLEWARE FUNCTIONS =====

/**
 * Middleware to validate request body
 * @param schema - Zod schema for validation
 * @returns Express middleware function
 */
export function validateBody(schema: ZodSchema) {
    return (req: Request, res: Response, next: NextFunction) => {
        try {
            const validatedData = schema.parse(req.body);
            req.body = validatedData; // Replace with validated data
            next();
        } catch (error) {
            if (error instanceof ZodError) {
                const validationError = new ValidationError(
                    'Validation failed',
                    { errors: error.errors }
                );
                return res.status(400).json(validationError.serialize());
            }
            next(error);
        }
    };
}

/**
 * Middleware to validate request query parameters
 * @param schema - Zod schema for validation
 * @returns Express middleware function
 */
export function validateQuery(schema: ZodSchema) {
    return (req: Request, res: Response, next: NextFunction) => {
        try {
            const validatedData = schema.parse(req.query);
            req.query = validatedData;
            next();
        } catch (error) {
            if (error instanceof ZodError) {
                const validationError = new ValidationError(
                    'Query validation failed',
                    { errors: error.errors }
                );
                return res.status(400).json(validationError.serialize());
            }
            next(error);
        }
    };
}

/**
 * Middleware to validate request parameters
 * @param schema - Zod schema for validation
 * @returns Express middleware function
 */
export function validateParams(schema: ZodSchema) {
    return (req: Request, res: Response, next: NextFunction) => {
        try {
            const validatedData = schema.parse(req.params);
            req.params = validatedData;
            next();
        } catch (error) {
            if (error instanceof ZodError) {
                const validationError = new ValidationError(
                    'Parameter validation failed',
                    { errors: error.errors }
                );
                return res.status(400).json(validationError.serialize());
            }
            next(error);
        }
    };
}

// ===== VALIDATION SCHEMAS =====

/**
 * User registration schema
 */
export const userRegistrationSchema = z.object({
    name: z.string()
        .min(2, 'Name must be at least 2 characters')
        .max(120, 'Name must be less than 120 characters')
        .trim(),
    
    email: z.string()
        .email('Invalid email format')
        .toLowerCase()
        .trim(),
    
    password: z.string()
        .min(8, 'Password must be at least 8 characters')
        .regex(
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
            'Password must contain lowercase, uppercase, and number'
        )
});

/**
 * User login schema
 */
export const userLoginSchema = z.object({
    email: z.string()
        .email('Invalid email format')
        .toLowerCase()
        .trim(),
    
    password: z.string()
        .min(1, 'Password is required')
});

/**
 * Change password schema
 */
export const changePasswordSchema = z.object({
    oldPassword: z.string()
        .min(1, 'Old password is required'),
    newPassword: z.string()
        .min(1, 'New password is required')
});

/**
 * Topic creation schema
 */
export const topicCreateSchema = z.object({
    title: z.string()
        .min(1, 'Title is required')
        .max(180, 'Title must be less than 180 characters')
        .trim(),
    
    description: z.string().trim()
        .max(5000, 'Description must be less than 5000 characters')
        .optional(),
    
    visibility: z.enum(['private', 'unlisted', 'public'])
        .default('private'),
    
    tags: z.array(z.string().trim())
        .max(10, 'Maximum 10 tags allowed')
        .default([])
});

/**
 * Topic update schema
 */
export const topicUpdateSchema = z.object({
    title: z.string()
        .min(1, 'Title is required')
        .max(180, 'Title must be less than 180 characters')
        .trim()
        .optional(),
    
    description: z.string()
        .max(5000, 'Description must be less than 5000 characters')
        .trim()
        .optional(),
    
    visibility: z.enum(['private', 'unlisted', 'public'])
        .optional(),
    
    tags: z.array(z.string().trim())
        .max(10, 'Maximum 10 tags allowed')
        .optional()
});

/**
 * Message creation schema
 */
export const messageCreateSchema = z.object({
    content: z.string()
        .min(1, 'Message content is required')
        .max(10000, 'Message must be less than 10000 characters')
        .trim(),
    
    parentMessageId: z.string()
        .optional()
        .transform(val => val ?? null)
});

/**
 * Pagination query schema
 */
export const paginationSchema = z.object({
    page: z.string()
        .transform(val => parseInt(val, 10))
        .pipe(z.number().min(1).default(1))
        .optional(),
    
    limit: z.string()
        .transform(val => parseInt(val, 10))
        .pipe(z.number().min(1).max(100).default(10))
        .optional(),
    
    sortBy: z.enum(['createdAt', 'updatedAt', 'title'])
        .default('createdAt')
        .optional(),
    
    sortOrder: z.enum(['asc', 'desc'])
        .default('desc')
        .optional()
});

/**
 * ID parameter schema
 */
export const idParamSchema = z.object({
    id: z.string()
        .min(1, 'ID is required')
        .regex(/^[0-9a-fA-F]{24}$/, 'Invalid ID format')
});

/**
 * Search query schema
 */
export const searchQuerySchema = z.object({
    q: z.string()
        .min(1, 'Search query is required')
        .max(100, 'Search query too long')
        .trim(),
    
    type: z.enum(['topics', 'messages', 'all'])
        .default('all')
        .optional()
});

// ===== HELPER FUNCTIONS =====

/**
 * Sanitize string input to prevent XSS
 * @param input - String to sanitize
 * @returns Sanitized string
 */
export function sanitizeString(input: string): string {
    return input
        .replace(/[<>]/g, '') // Remove < and >
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+=/gi, '') // Remove event handlers
        .trim();
}

/**
 * Validate MongoDB ObjectId format
 * @param id - ID to validate
 * @returns True if valid ObjectId format
 */
export function isValidObjectId(id: string): boolean {
    return /^[0-9a-fA-F]{24}$/.test(id);
}
