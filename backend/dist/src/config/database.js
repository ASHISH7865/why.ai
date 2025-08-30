import mongoose from 'mongoose';
import env from './env.js';
import logger from './logger.js';
export async function connectDatabase() {
    try {
        await mongoose.connect(env.MONGODB_URI);
        logger.info('Connected to MongoDB');
        // Handle connection events
        mongoose.connection.on('error', (error) => {
            logger.error('MongoDB connection error:', error);
        });
        mongoose.connection.on('disconnected', () => {
            logger.warn('MongoDB disconnected');
        });
        process.on('SIGINT', () => {
            mongoose.connection.close().then(() => {
                logger.info('MongoDB connection closed through app termination');
                process.exit(0);
            }).catch((error) => {
                logger.error('Error closing MongoDB connection:', error);
                process.exit(1);
            });
        });
    }
    catch (error) {
        logger.error('Failed to connect to MongoDB:', error);
        process.exit(1);
    }
}
export async function disconnectDatabase() {
    try {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');
    }
    catch (error) {
        logger.error('Error closing MongoDB connection:', error);
    }
}
