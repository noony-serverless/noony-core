/**
 * Google Cloud Function: Create User
 * 
 * This file creates a Google Cloud Function that handles user creation requests.
 * It acts as a simple wrapper around our Noony handler, making it compatible
 * with Google Cloud Functions runtime.
 * 
 * Endpoint: POST /
 * Function name: createUser
 * Expected payload: { name, email, age, department?, phoneNumber?, bio? }
 * 
 * How it works:
 * 1. Google Cloud Functions calls this function when HTTP requests arrive
 * 2. We pass the request to our Noony createUserHandler 
 * 3. The handler processes the request through its middleware pipeline
 * 4. Response is sent back through Google Cloud Functions
 */

// Import the Google Cloud Functions framework
import { http } from '@google-cloud/functions-framework';

// Import our Noony handler that contains all the business logic
import { createUserHandler } from './handlers/user.handlers';

/**
 * Export the Google Cloud Function
 * 
 * The http() function from Google Cloud Functions framework creates an HTTP function
 * that will be deployed to Google Cloud and can handle HTTP requests.
 * 
 * Parameters:
 * - 'createUser': The name of the function (used in deployment)
 * - (req, res): Standard HTTP request/response callback
 */
export const createUser = http('createUser', (req, res) => {
  // Execute our Noony handler - this runs the full middleware pipeline:
  // 1. Error handling
  // 2. Authentication (checks for valid JWT token)
  // 3. Authorization (checks user permissions)
  // 4. Request validation (validates JSON body against schema)
  // 5. Business logic (creates the user in database)
  // 6. Response formatting (wraps response in standard format)
  return createUserHandler.execute(req, res);
});