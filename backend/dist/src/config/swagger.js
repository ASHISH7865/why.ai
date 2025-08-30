import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Why.AI API',
            version: '1.0.0',
            description: 'First-principles learning platform with contextual exploration',
            contact: {
                name: 'Why.AI Team',
                email: 'support@why.ai'
            },
            license: {
                name: 'ISC',
                url: 'https://opensource.org/licenses/ISC'
            }
        },
        servers: [
            {
                url: 'http://localhost:9001',
                description: 'Development server'
            },
            {
                url: 'https://api.why.ai',
                description: 'Production server'
            }
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            },
            schemas: {
                Error: {
                    type: 'object',
                    properties: {
                        message: {
                            type: 'string',
                            description: 'Error message'
                        },
                        status: {
                            type: 'string',
                            description: 'Error status'
                        },
                        timestamp: {
                            type: 'string',
                            format: 'date-time',
                            description: 'Error timestamp'
                        }
                    }
                },
                HealthResponse: {
                    type: 'object',
                    properties: {
                        status: {
                            type: 'string',
                            enum: ['OK', 'DEGRADED', 'ERROR'],
                            description: 'Health status'
                        },
                        timestamp: {
                            type: 'string',
                            format: 'date-time',
                            description: 'Response timestamp'
                        },
                        uptime: {
                            type: 'number',
                            description: 'Server uptime in seconds'
                        },
                        environment: {
                            type: 'string',
                            description: 'Environment name'
                        },
                        version: {
                            type: 'string',
                            description: 'API version'
                        }
                    }
                }
            }
        },
        security: [
            {
                bearerAuth: []
            }
        ]
    },
    apis: ['./src/routes/*.ts', './src/index.ts'] // Path to the API docs
};
const specs = swaggerJsdoc(options);
export function setupSwagger(app) {
    // Serve Swagger UI
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs, {
        customCss: '.swagger-ui .topbar { display: none }',
        customSiteTitle: 'Why.AI API Documentation'
    }));
    // Serve OpenAPI spec as JSON
    app.get('/api-docs.json', (req, res) => {
        res.setHeader('Content-Type', 'application/json');
        res.send(specs);
    });
}
