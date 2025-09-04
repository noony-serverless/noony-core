/**
 * Google Cloud Function: Get User by ID
 *
 * This function retrieves a specific user by their unique ID.
 * It demonstrates how to handle URL parameters and implement proper authorization.
 *
 * Endpoint: GET /{userId}
 * Function name: getUser
 * URL Parameter: userId (UUID format)
 *
 * Authorization Rules:
 * - Users can always view their own profile
 * - Users with 'user:read' permission can view any profile
 * - Admin users can view any profile
 *
 * How it works:
 * 1. Extracts user ID from URL path (e.g., /123e4567-e89b-12d3-a456-426614174000)
 * 2. Validates the user ID format (must be valid UUID)
 * 3. Checks if current user has permission to view the requested profile
 * 4. Retrieves user data from the database
 * 5. Returns user information in standardized format
 *
 * Example successful response:
 * {
 *   "success": true,
 *   "payload": {
 *     "user": { "id": "...", "name": "John", "email": "john@example.com", ... },
 *     "requestedBy": { "userId": "...", "name": "...", "isOwnProfile": true }
 *   }
 * }
 */

// Import the Google Cloud Functions framework
import { http } from '@google-cloud/functions-framework';

// Import our Noony handler that contains the business logic
import { getUserHandler } from './handlers/user.handlers';

/**
 * Export the Google Cloud Function for getting a user by ID
 *
 * This function handles GET requests to retrieve user information.
 * The user ID should be passed as part of the URL path.
 */
export const getUser = http('getUser', (req, res) => {
  // Execute our Noony handler - this runs the middleware pipeline:
  // 1. Error handling
  // 2. Authentication (validates JWT token from Authorization header)
  // 3. Parameter extraction (gets user ID from URL)
  // 4. Authorization check (ensures user can view this profile)
  // 5. Database lookup (retrieves user data)
  // 6. Response formatting (returns user data in standard format)
  return getUserHandler.execute(req, res);
});
