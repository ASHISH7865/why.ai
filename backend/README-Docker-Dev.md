# Docker Development Setup with Watch Mode

This setup allows you to run your Node.js/TypeScript application in Docker with hot reloading enabled.

## Quick Start

1. **Start the development environment:**
   ```bash
   npm run docker:dev
   ```

2. **Stop the development environment:**
   ```bash
   npm run docker:dev:down
   ```

3. **View application logs:**
   ```bash
   npm run docker:dev:logs
   ```

## What's Included

- **Hot Reloading**: Your source code changes will automatically restart the application
- **Development Dependencies**: All dev dependencies are included for TypeScript compilation
- **Volume Mounts**: Source code is mounted for live updates
- **Full Stack**: MongoDB, Redis, and Mongo Express are included
- **Environment Variables**: Uses your `.env` file for configuration

## Available Services

- **App**: Your Node.js application on port 9001
- **MongoDB**: Database on port 27017
- **Redis**: Cache on port 6379
- **Mongo Express**: Database admin interface on port 8081

## How It Works

1. **Dockerfile.dev**: Uses the development Dockerfile that includes all dependencies
2. **Volume Mounts**: Source code is mounted to enable hot reloading
3. **Watch Mode**: Uses `tsx --watch` to automatically restart on file changes
4. **Environment**: Set to development mode with appropriate logging

## File Changes

When you modify files in the `src/` directory, the application will automatically restart thanks to the `tsx --watch` command and the volume mounts.

## Troubleshooting

- If you encounter permission issues, ensure your `.env` file has the correct permissions
- If the app doesn't restart on changes, check that the volume mounts are working correctly
- Use `docker-compose -f docker-compose.dev.yml logs app` to debug issues
