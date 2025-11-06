/**
 * Google Cloud Function: List Users with Pagination and Filtering
 *
 * This function provides a comprehensive user listing API with advanced filtering,
 * pagination, and sorting capabilities. Perfect for admin dashboards and user management.
 *
 * Endpoint: GET /?page=1&limit=10&search=john&department=engineering
 * Function name: listUsers
 *
 * Required Permissions:
 * - 'user:list' OR 'admin:users'
 *
 * Query Parameters (all optional):
 * - page: Page number (default: 1)
 * - limit: Users per page (default: 10, max: 100)
 * - search: Text search in name, email, department, bio
 * - department: Filter by specific department
 * - sortBy: Sort field (name, email, age, department, createdAt, updatedAt)
 * - sortOrder: Sort direction (asc, desc)
 * - minAge, maxAge: Age range filtering
 * - includeDeleted: Include soft-deleted users (admin only)
 *
 * Example request:
 * GET /?page=2&limit=20&search=engineer&department=tech&sortBy=name&sortOrder=asc
 *
 * Example successful response:
 * {
 *   "success": true,
 *   "payload": {
 *     "items": [...users...],
 *     "pagination": {
 *       "page": 2,
 *       "limit": 20,
 *       "total": 150,
 *       "totalPages": 8,
 *       "hasNextPage": true,
 *       "hasPreviousPage": true
 *     },
 *     "filters": {
 *       "search": "engineer",
 *       "department": "tech",
 *       "sortBy": "name",
 *       "sortOrder": "asc"
 *     }
 *   }
 * }
 */

// Import the Google Cloud Functions framework
import { http } from '@google-cloud/functions-framework';

// Import our Noony handler that contains the business logic
import { listUsersHandler } from './handlers/user.handlers';

/**
 * Export the Google Cloud Function for listing users
 *
 * This function handles GET requests to retrieve a paginated list of users
 * with comprehensive filtering and sorting options.
 */
export const listUsers = http('listUsers', (req, res) => {
  // Execute our Noony handler - this runs the middleware pipeline:
  // 1. Error handling
  // 2. Authentication (validates JWT token)
  // 3. Authorization (checks for user:list or admin:users permissions)
  // 4. Query parameter parsing and validation
  // 5. Database query with filters, pagination, and sorting
  // 6. Response formatting with metadata
  return listUsersHandler.execute(req, res);
});
