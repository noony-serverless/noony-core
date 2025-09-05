#!/usr/bin/env node

/**
 * Generate Test JWT Tokens
 * 
 * This script generates valid JWT tokens for testing the Guard System Showcase.
 * The tokens are signed with the same secret used by the application.
 */

const jwt = require('jsonwebtoken');

// Configuration (matches guard.config.ts)
const JWT_SECRET = process.env.JWT_SECRET || 'demo-secret-key-for-development';
const JWT_ISSUER = 'guard-system-showcase';
const JWT_AUDIENCE = 'demo-users';

// Demo users with their roles and permissions
const demoUsers = [
  {
    type: 'basic',
    userId: 'user-basic-001',
    name: 'John User',
    email: 'john.user@example.com',
    roles: ['user'],
    permissions: ['user:profile:read', 'user:profile:update', 'content:create']
  },
  {
    type: 'creator',
    userId: 'user-creator-001', 
    name: 'Sarah Creator',
    email: 'sarah.creator@example.com',
    roles: ['creator'],
    permissions: ['user:profile:read', 'user:profile:update', 'content:create', 'user:read']
  },
  {
    type: 'moderator',
    userId: 'user-moderator-001',
    name: 'Mike Moderator', 
    email: 'mike.moderator@example.com',
    roles: ['moderator'],
    permissions: ['user:profile:read', 'user:profile:update', 'user:read', 'content:create', 'content:moderate', 'user:update']
  },
  {
    type: 'manager',
    userId: 'user-manager-001',
    name: 'Lisa Manager',
    email: 'lisa.manager@example.com', 
    roles: ['dept-manager'],
    permissions: ['user:profile:read', 'user:profile:update', 'user:read', 'user:create', 'user:update', 'dept:engineering:read']
  },
  {
    type: 'admin',
    userId: 'user-admin-001',
    name: 'Alice Administrator',
    email: 'alice.admin@example.com',
    roles: ['admin'],
    permissions: ['admin:users', 'admin:system', 'system:monitor', 'system:backup', 'dept:engineering:read', 'dept:hr:read', 'dept:finance:read', 'content:moderate']
  },
  {
    type: 'superadmin', 
    userId: 'user-superadmin-001',
    name: 'Bob SuperAdmin',
    email: 'bob.superadmin@example.com',
    roles: ['superadmin'],
    permissions: ['admin:users', 'admin:system', 'admin:security', 'system:monitor', 'system:backup', 'dept:engineering:read', 'dept:hr:read', 'dept:finance:read', 'content:moderate', 'user:delete']
  },
  {
    type: 'restricted',
    userId: 'user-restricted-001',
    name: 'Charlie Restricted', 
    email: 'charlie.restricted@example.com',
    roles: ['restricted'],
    permissions: ['user:profile:read']
  }
];

/**
 * Generate JWT token for a user with optional test run ID for isolation
 */
function generateToken(user, testRunId = null) {
  const userId = testRunId ? `${user.userId}-${testRunId}` : user.userId;
  const email = testRunId ? user.email.replace('@', `+${testRunId}@`) : user.email;
  
  const payload = {
    sub: userId,
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60), // 24 hours from now
    iat: Math.floor(Date.now() / 1000),
    name: user.name,
    email: email,
    roles: user.roles,
    permissions: user.permissions,
    type: 'access',
    testRunId: testRunId || 'default'
  };

  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

/**
 * Generate all tokens and output in shell script format
 */
function generateAllTokens(testRunId = null) {
  console.log('#!/bin/bash');
  console.log('# Generated JWT tokens for Guard System Showcase testing');
  console.log('# Generated at:', new Date().toISOString());
  console.log('# Test Run ID:', testRunId || 'default');
  console.log('# JWT Secret:', JWT_SECRET);
  console.log('');
  
  // Generate tokens
  demoUsers.forEach(user => {
    const token = generateToken(user, testRunId);
    console.log(`TOKEN_${user.type}="${token}"`);
  });
  
  console.log('');
  console.log('# User information');
  demoUsers.forEach(user => {
    const userId = testRunId ? `${user.userId}-${testRunId}` : user.userId;
    const email = testRunId ? user.email.replace('@', `+${testRunId}@`) : user.email;
    console.log(`INFO_${user.type}="${userId}:${email}:${user.name}"`);
  });
}

/**
 * Main execution
 */
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log('Generate Test JWT Tokens');
    console.log('');
    console.log('Usage:');
    console.log('  node generate-test-tokens.js                        # Generate all tokens');
    console.log('  node generate-test-tokens.js --user basic           # Generate specific user token');
    console.log('  node generate-test-tokens.js --test-run-id test123  # Generate with test run ID');
    console.log('  node generate-test-tokens.js --verify TOKEN         # Verify a token');
    console.log('');
    console.log('Options:');
    console.log('  --user TYPE        Generate token for specific user type');
    console.log('  --test-run-id ID   Generate unique tokens for isolated testing');
    console.log('  --verify TOKEN     Verify and decode a JWT token');
    console.log('  --help, -h         Show this help message');
    return;
  }
  
  if (args.includes('--verify')) {
    const tokenIndex = args.indexOf('--verify') + 1;
    const token = args[tokenIndex];
    if (!token) {
      console.error('Error: No token provided for verification');
      process.exit(1);
    }
    
    try {
      const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
      console.log('Token is valid!');
      console.log('Decoded payload:');
      console.log(JSON.stringify(decoded, null, 2));
    } catch (error) {
      console.error('Token verification failed:', error.message);
      process.exit(1);
    }
    return;
  }
  
  // Check for test run ID
  let testRunId = null;
  if (args.includes('--test-run-id')) {
    const runIdIndex = args.indexOf('--test-run-id') + 1;
    testRunId = args[runIdIndex];
    if (!testRunId) {
      console.error('Error: No test run ID provided');
      process.exit(1);
    }
  }

  if (args.includes('--user')) {
    const userIndex = args.indexOf('--user') + 1;
    const userType = args[userIndex];
    const user = demoUsers.find(u => u.type === userType);
    
    if (!user) {
      console.error(`Error: Unknown user type '${userType}'`);
      console.error('Available types:', demoUsers.map(u => u.type).join(', '));
      process.exit(1);
    }
    
    const token = generateToken(user, testRunId);
    console.log(token);
    return;
  }
  
  // Default: generate all tokens
  generateAllTokens(testRunId);
}