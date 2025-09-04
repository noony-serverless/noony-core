/**
 * Development Server
 *
 * Local development server for testing the Guard System Showcase
 * with a REST API for interactive testing and demonstration.
 *
 * @module Server
 * @version 1.0.0
 */

import express from 'express';
import cors from 'cors';
import { authHandlers } from './api/handlers/auth-handlers';

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'guard-system-showcase',
    timestamp: new Date().toISOString()
  });
});

// Authentication and authorization endpoints
app.post('/api/auth/authenticate', authHandlers.authenticate);
app.post('/api/auth/validate', authHandlers.validateToken);
app.get('/api/auth/user', authHandlers.getCurrentUser);
app.get('/api/permissions/user/:userId', authHandlers.getUserPermissions);
app.get('/api/auth/stats', authHandlers.getAuthStats);
app.get('/api/security/incidents', authHandlers.getSecurityIncidents);

// Error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not found',
    message: `Route ${req.method} ${req.path} not found`
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Guard System Showcase server running on port ${port}`);
  console.log(`📖 API documentation: http://localhost:${port}/health`);
  console.log(`🔐 Authentication endpoint: http://localhost:${port}/api/auth/token`);
  console.log(`🛡️ Guard endpoint: http://localhost:${port}/api/auth/guard`);
  console.log(`📊 Stats endpoint: http://localhost:${port}/api/stats`);
});

export default app;