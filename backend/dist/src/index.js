import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { createServer } from 'http';
// Import configurations
import env from './config/env.js';
import logger from './config/logger.js';
import { connectDatabase, disconnectDatabase } from './config/database.js';
import { connectRedis, disconnectRedis } from './config/redis.js';
// Import middleware
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { apiRateLimit } from './middleware/rateLimit.js';
// Import routes (we'll create these next)
// import authRoutes from './routes/auth.routes.js';
// import topicRoutes from './routes/topic.routes.js';
// import messageRoutes from './routes/message.routes.js';
// import highlightRoutes from './routes/highlight.routes.js';
// Create Express app
const app = express();
const server = createServer(app);
// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    crossOriginEmbedderPolicy: false,
}));
// CORS configuration
app.use(cors({
    origin: env.CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));
// Compression middleware
app.use(compression());
// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// Request logging middleware
app.use((req, res, next) => {
    const start = Date.now();
    // Add request ID
    req.headers['x-request-id'] = req.headers['x-request-id'] ??
        `req_${Date.now().toString()}_${Math.random().toString(36).substring(2, 9)}`;
    logger.info('Incoming request', {
        method: req.method,
        path: req.path,
        query: req.query,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.headers['x-request-id']
    });
    // Log response
    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('Request completed', {
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            duration: `${duration.toString()}ms`,
            requestId: req.headers['x-request-id']
        });
    });
    next();
});
// Rate limiting
app.use(apiRateLimit());
app.get('/healthz', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: env.NODE_ENV,
        version: process.env.npm_package_version ?? '1.0.0'
    });
});
app.get('/healthz/detailed', async (req, res) => {
    try {
        // Check database connection
        const dbStatus = await checkDatabaseHealth();
        // Check Redis connection
        const redisStatus = await checkRedisHealth();
        const healthStatus = {
            status: dbStatus && redisStatus ? 'OK' : 'DEGRADED',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            environment: env.NODE_ENV,
            version: process.env.npm_package_version ?? '1.0.0',
            services: {
                database: dbStatus,
                redis: redisStatus
            }
        };
        const statusCode = healthStatus.status === 'OK' ? 200 : 503;
        res.status(statusCode).json(healthStatus);
    }
    catch (error) {
        logger.error('Health check failed:', error);
        res.status(503).json({
            status: 'ERROR',
            timestamp: new Date().toISOString(),
            error: 'Health check failed'
        });
    }
});
// API routes
// API versioning
app.use('/api/v1', (req, res, next) => {
    logger.info('API v1 request', {
        method: req.method,
        path: req.path,
        requestId: req.headers['x-request-id']
    });
    next();
});
// Mount routes (we'll uncomment these as we build them)
// app.use('/api/v1/auth', authRoutes);
// app.use('/api/v1/topics', topicRoutes);
// app.use('/api/v1/messages', messageRoutes);
// app.use('/api/v1/highlights', highlightRoutes);
// Temporary placeholder route
app.get('/api/v1', (req, res) => {
    res.json({
        message: 'Why.AI API v1',
        version: '1.0.0',
        status: 'active',
        endpoints: {
            auth: '/api/v1/auth',
            topics: '/api/v1/topics',
            messages: '/api/v1/messages',
            highlights: '/api/v1/highlights'
        }
    });
});
// Error handling
// 404 handler (must be before error handler)
app.use(notFoundHandler);
// Global error handler (must be last)
app.use(errorHandler);
// Health check functions
async function checkDatabaseHealth() {
    try {
        // Simple database ping
        await import('mongoose');
        const { default: mongoose } = await import('mongoose');
        return mongoose.connection.readyState === 1;
    }
    catch (error) {
        logger.error('Database health check failed:', error);
        return false;
    }
}
async function checkRedisHealth() {
    try {
        const redisClient = await import('./config/redis.js');
        await redisClient.default.ping();
        return true;
    }
    catch (error) {
        logger.error('Redis health check failed:', error);
        return false;
    }
}
// Graceful shutdown
async function gracefulShutdown(signal) {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);
    // Stop accepting new requests
    server.close((err) => {
        if (err) {
            logger.error('Error during server shutdown:', err);
            process.exit(1);
        }
        logger.info('HTTP server closed');
    });
    try {
        // Close database connection
        await disconnectDatabase();
        logger.info('Database connection closed');
        // Close Redis connection
        await disconnectRedis();
        logger.info('Redis connection closed');
        logger.info('Graceful shutdown completed');
        process.exit(0);
    }
    catch (error) {
        logger.error('Error during graceful shutdown:', error);
        process.exit(1);
    }
}
// Handle shutdown signals
process.on('SIGTERM', () => void gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => void gracefulShutdown('SIGINT'));
// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});
// Server startup
async function startServer() {
    try {
        logger.info('Starting Why.AI backend server...');
        // Connect to database
        await connectDatabase();
        logger.info('Database connected successfully');
        // Connect to Redis
        await connectRedis();
        logger.info('Redis connected successfully');
        // Start HTTP server
        server.listen(env.PORT, () => {
            logger.info(`🚀 Why.AI backend server running on port ${env.PORT.toString()}`);
            logger.info(`Environment: ${env.NODE_ENV}`);
            logger.info(`Health check: http://localhost:${env.PORT.toString()}/healthz`);
            logger.info(`API docs: http://localhost:${env.PORT.toString()}/api/v1`);
        });
    }
    catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}
// Start the server
void startServer();
export default app;
