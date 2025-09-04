/**
 * Google Cloud Function: Health Check
 * 
 * This is a simple health check endpoint that can be used to verify that
 * the service is running and responding to requests. It's commonly used by:
 * - Load balancers to check if the service is healthy
 * - Monitoring systems to detect outages
 * - Deployment pipelines to verify successful deployments
 * 
 * Endpoint: GET /
 * Function name: health
 * Authentication: None required (public endpoint)
 * 
 * This is the simplest function - no middleware, no authentication,
 * just a basic response to confirm the service is alive.
 * 
 * Example successful response:
 * {
 *   "status": "ok",
 *   "timestamp": "2025-09-04T01:15:30.123Z",
 *   "service": "noony-fastify-production-api"
 * }
 * 
 * Use cases:
 * - Kubernetes liveness probes: GET /health
 * - Load balancer health checks
 * - Uptime monitoring services
 * - Quick smoke tests after deployment
 */

// Import the Google Cloud Functions framework
import { http } from '@google-cloud/functions-framework';

/**
 * Export the Google Cloud Function for health checks
 * 
 * This is a minimal function that doesn't use any Noony middleware.
 * It directly responds with a simple JSON status message.
 * 
 * No authentication required - this is intentionally a public endpoint
 * so monitoring systems can check if the service is alive without credentials.
 */
export const health = http('health', (req, res) => {
  // Set proper HTTP status code (200 = OK)
  res.status(200);
  
  // Return a simple JSON response with health information
  res.json({
    // Status indicator - "ok" means the service is healthy
    status: 'ok',
    
    // Current timestamp - useful for checking if the service is current
    timestamp: new Date().toISOString(),
    
    // Service identifier - helps identify which service responded
    service: 'noony-fastify-production-api',
    
    // Optional: You could add more health indicators here:
    // - Database connectivity status
    // - External service dependencies
    // - Memory usage
    // - Version information
  });
});