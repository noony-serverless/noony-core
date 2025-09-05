/**
 * Demo Data Generator and Management
 *
 * Comprehensive demo data generation for the Guard System Showcase.
 * Creates realistic test users, roles, permissions, and scenarios to
 * demonstrate all authentication and authorization capabilities.
 *
 * @module DemoData
 * @version 1.0.0
 */

import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import {
  DemoUser,
  Role,
  Permission,
  SecurityTestScenario,
} from '@/types/auth.types';
import { getConfig } from '@/config/environment.config';

// ============================================================================
// PERMISSION DEFINITIONS
// ============================================================================

/**
 * Complete permission catalog for the demo system
 */
export const DEMO_PERMISSIONS: Permission[] = [
  // User Management Permissions
  {
    id: 'user:create',
    name: 'Create Users',
    description: 'Create new user accounts',
    category: 'user-management',
    resource: 'user',
    action: 'create',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: false,
    },
  },
  {
    id: 'user:read',
    name: 'Read Users',
    description: 'View user account information',
    category: 'user-management',
    resource: 'user',
    action: 'read',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: false,
    },
  },
  {
    id: 'user:update',
    name: 'Update Users',
    description: 'Modify user account information',
    category: 'user-management',
    resource: 'user',
    action: 'update',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },
  {
    id: 'user:delete',
    name: 'Delete Users',
    description: 'Remove user accounts',
    category: 'user-management',
    resource: 'user',
    action: 'delete',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },

  // Profile Management
  {
    id: 'user:profile:read',
    name: 'Read Own Profile',
    description: 'View own user profile',
    category: 'profile',
    resource: 'user-profile',
    action: 'read',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: false,
    },
  },
  {
    id: 'user:profile:update',
    name: 'Update Own Profile',
    description: 'Modify own user profile',
    category: 'profile',
    resource: 'user-profile',
    action: 'update',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: false,
    },
  },

  // Administrative Permissions
  {
    id: 'admin:users',
    name: 'User Administration',
    description: 'Full administrative access to user management',
    category: 'administration',
    resource: 'user',
    action: '*',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },
  {
    id: 'admin:system',
    name: 'System Administration',
    description: 'System-level administrative access',
    category: 'administration',
    resource: 'system',
    action: '*',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },
  {
    id: 'admin:security',
    name: 'Security Administration',
    description: 'Security and compliance administrative access',
    category: 'administration',
    resource: 'security',
    action: '*',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },

  // Department-based Permissions
  {
    id: 'dept:engineering:read',
    name: 'Engineering Department Read',
    description: 'Read access to engineering department resources',
    category: 'department',
    resource: 'department-engineering',
    action: 'read',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: false,
    },
  },
  {
    id: 'dept:hr:read',
    name: 'HR Department Read',
    description: 'Read access to HR department resources',
    category: 'department',
    resource: 'department-hr',
    action: 'read',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },
  {
    id: 'dept:finance:read',
    name: 'Finance Department Read',
    description: 'Read access to finance department resources',
    category: 'department',
    resource: 'department-finance',
    action: 'read',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },

  // Content Management
  {
    id: 'content:create',
    name: 'Create Content',
    description: 'Create new content items',
    category: 'content',
    resource: 'content',
    action: 'create',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: false,
    },
  },
  {
    id: 'content:moderate',
    name: 'Moderate Content',
    description: 'Moderate and approve content',
    category: 'content',
    resource: 'content',
    action: 'moderate',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },

  // System Permissions
  {
    id: 'system:monitor',
    name: 'System Monitoring',
    description: 'Access to system monitoring and metrics',
    category: 'system',
    resource: 'system',
    action: 'monitor',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },
  {
    id: 'system:backup',
    name: 'System Backup',
    description: 'Create and manage system backups',
    category: 'system',
    resource: 'system',
    action: 'backup',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      sensitive: true,
    },
  },
];

// ============================================================================
// ROLE DEFINITIONS
// ============================================================================

/**
 * Role hierarchy and definitions
 */
export const DEMO_ROLES: Role[] = [
  // Basic User Role
  {
    id: 'user',
    name: 'User',
    description: 'Standard user with basic permissions',
    permissions: ['user:profile:read', 'user:profile:update', 'content:create'],
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      priority: 1,
      system: true,
    },
  },

  // Content Creator Role
  {
    id: 'creator',
    name: 'Content Creator',
    description: 'User with enhanced content creation permissions',
    permissions: [
      'user:profile:read',
      'user:profile:update',
      'content:create',
      'user:read', // Can view other users
    ],
    parent: 'user',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      priority: 2,
      system: true,
    },
  },

  // Moderator Role
  {
    id: 'moderator',
    name: 'Moderator',
    description: 'Content moderator with user management permissions',
    permissions: [
      'user:profile:read',
      'user:profile:update',
      'user:read',
      'content:create',
      'content:moderate',
      'user:update', // Limited user management
    ],
    parent: 'creator',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      priority: 3,
      system: true,
    },
  },

  // Department Manager Role
  {
    id: 'dept-manager',
    name: 'Department Manager',
    description: 'Manager with department-specific permissions',
    permissions: [
      'user:profile:read',
      'user:profile:update',
      'user:read',
      'user:create',
      'user:update',
      'dept:engineering:read', // Example department
    ],
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      priority: 4,
      system: true,
    },
  },

  // Administrator Role
  {
    id: 'admin',
    name: 'Administrator',
    description: 'System administrator with full permissions',
    permissions: [
      'admin:users',
      'admin:system',
      'system:monitor',
      'system:backup',
      'dept:engineering:read',
      'dept:hr:read',
      'dept:finance:read',
      'content:moderate',
    ],
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      priority: 5,
      system: true,
    },
  },

  // Super Administrator Role
  {
    id: 'superadmin',
    name: 'Super Administrator',
    description: 'Highest level administrator with all permissions',
    permissions: [
      'admin:users',
      'admin:system',
      'admin:security',
      'system:monitor',
      'system:backup',
      'dept:engineering:read',
      'dept:hr:read',
      'dept:finance:read',
      'content:moderate',
      'user:delete', // Only super admin can delete users
    ],
    parent: 'admin',
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      priority: 10,
      system: true,
    },
  },

  // Restricted User Role (for testing)
  {
    id: 'restricted',
    name: 'Restricted User',
    description: 'Limited user with minimal permissions (for testing)',
    permissions: ['user:profile:read'],
    metadata: {
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      priority: 0,
      system: true,
    },
  },
];

// ============================================================================
// DEMO USER GENERATOR
// ============================================================================

/**
 * Generate comprehensive demo users for testing all guard capabilities
 */
export class DemoDataGenerator {
  private readonly config = getConfig();

  /**
   * Generate a complete set of demo users
   */
  async generateDemoUsers(): Promise<DemoUser[]> {
    const users: DemoUser[] = [];

    // Add predefined test users
    users.push(...(await this.createPredefinedUsers()));

    // Add random users for load testing
    const randomUserCount = Math.min(
      this.config.DEMO_USER_COUNT - users.length,
      100
    );
    for (let i = 0; i < randomUserCount; i++) {
      users.push(await this.createRandomUser());
    }

    console.log(`📊 Generated ${users.length} demo users`);
    return users;
  }

  /**
   * Create predefined test users for specific scenarios
   */
  private async createPredefinedUsers(): Promise<DemoUser[]> {
    const users: DemoUser[] = [];

    // Basic User - Standard permissions
    users.push(
      await this.createDemoUser({
        userId: 'user-basic-001',
        name: 'John User',
        email: 'john.user@example.com',
        roles: ['user'],
        scenario: 'Basic user with standard permissions',
        type: 'basic',
        expectedBehavior: {
          'GET /demo/plain/basic': 'allow',
          'POST /demo/plain/advanced': 'deny',
          'GET /demo/wildcard/admin': 'deny',
          'GET /demo/expression/simple': 'deny',
        },
      })
    );

    // Content Creator - Enhanced permissions
    users.push(
      await this.createDemoUser({
        userId: 'user-creator-001',
        name: 'Sarah Creator',
        email: 'sarah.creator@example.com',
        roles: ['creator'],
        scenario: 'Content creator with enhanced permissions',
        type: 'basic',
        expectedBehavior: {
          'GET /demo/plain/basic': 'allow',
          'POST /demo/plain/advanced': 'deny',
          'GET /demo/wildcard/admin': 'deny',
          'GET /demo/expression/simple': 'allow',
        },
      })
    );

    // Moderator - Content management permissions
    users.push(
      await this.createDemoUser({
        userId: 'user-moderator-001',
        name: 'Mike Moderator',
        email: 'mike.moderator@example.com',
        roles: ['moderator'],
        scenario: 'Content moderator with user management permissions',
        type: 'moderator',
        expectedBehavior: {
          'GET /demo/plain/basic': 'allow',
          'POST /demo/plain/advanced': 'allow',
          'GET /demo/wildcard/admin': 'deny',
          'GET /demo/expression/simple': 'allow',
        },
      })
    );

    // Department Manager - Department-specific permissions
    users.push(
      await this.createDemoUser({
        userId: 'user-manager-001',
        name: 'Lisa Manager',
        email: 'lisa.manager@example.com',
        roles: ['dept-manager'],
        scenario: 'Department manager with hierarchical permissions',
        type: 'moderator',
        expectedBehavior: {
          'GET /demo/plain/basic': 'allow',
          'POST /demo/plain/advanced': 'allow',
          'GET /demo/wildcard/admin': 'deny',
          'GET /demo/wildcard/department': 'allow',
          'GET /demo/expression/simple': 'allow',
        },
      })
    );

    // Administrator - Full system access
    users.push(
      await this.createDemoUser({
        userId: 'user-admin-001',
        name: 'Alice Administrator',
        email: 'alice.admin@example.com',
        roles: ['admin'],
        scenario: 'System administrator with full permissions',
        type: 'admin',
        expectedBehavior: {
          'GET /demo/plain/basic': 'allow',
          'POST /demo/plain/advanced': 'allow',
          'GET /demo/wildcard/admin': 'allow',
          'GET /demo/wildcard/department': 'allow',
          'GET /demo/expression/simple': 'allow',
          'GET /demo/expression/complex': 'allow',
        },
      })
    );

    // Super Administrator - All permissions
    users.push(
      await this.createDemoUser({
        userId: 'user-superadmin-001',
        name: 'Bob SuperAdmin',
        email: 'bob.superadmin@example.com',
        roles: ['superadmin'],
        scenario: 'Super administrator with all permissions',
        type: 'admin',
        expectedBehavior: {
          'GET /demo/plain/basic': 'allow',
          'POST /demo/plain/advanced': 'allow',
          'GET /demo/wildcard/admin': 'allow',
          'GET /demo/wildcard/department': 'allow',
          'GET /demo/expression/simple': 'allow',
          'GET /demo/expression/complex': 'allow',
        },
      })
    );

    // Restricted User - Minimal permissions (for testing denials)
    users.push(
      await this.createDemoUser({
        userId: 'user-restricted-001',
        name: 'Charlie Restricted',
        email: 'charlie.restricted@example.com',
        roles: ['restricted'],
        scenario: 'Restricted user with minimal permissions for testing',
        type: 'restricted',
        expectedBehavior: {
          'GET /demo/plain/basic': 'deny',
          'POST /demo/plain/advanced': 'deny',
          'GET /demo/wildcard/admin': 'deny',
          'GET /demo/expression/simple': 'deny',
        },
      })
    );

    // Multi-Role User - Complex permission combination
    users.push(
      await this.createDemoUser({
        userId: 'user-multirole-001',
        name: 'Dana MultiRole',
        email: 'dana.multirole@example.com',
        roles: ['creator', 'dept-manager'],
        scenario: 'User with multiple roles for testing complex permissions',
        type: 'moderator',
        expectedBehavior: {
          'GET /demo/plain/basic': 'allow',
          'POST /demo/plain/advanced': 'allow',
          'GET /demo/wildcard/admin': 'deny',
          'GET /demo/wildcard/department': 'allow',
          'GET /demo/expression/simple': 'allow',
        },
      })
    );

    return users;
  }

  /**
   * Create a random demo user for load testing
   */
  private async createRandomUser(): Promise<DemoUser> {
    const names = [
      'Alex',
      'Morgan',
      'Jordan',
      'Taylor',
      'Casey',
      'Riley',
      'Avery',
      'Quinn',
    ];
    const surnames = [
      'Smith',
      'Johnson',
      'Williams',
      'Brown',
      'Jones',
      'Garcia',
      'Miller',
      'Davis',
    ];
    const departments = [
      'engineering',
      'marketing',
      'sales',
      'hr',
      'finance',
      'operations',
    ];
    const availableRoles = ['user', 'creator', 'moderator', 'dept-manager'];

    const firstName = names[Math.floor(Math.random() * names.length)];
    const lastName = surnames[Math.floor(Math.random() * surnames.length)];
    const department =
      departments[Math.floor(Math.random() * departments.length)];
    const role =
      availableRoles[Math.floor(Math.random() * availableRoles.length)];

    const userId = `user-${department}-${Math.random().toString(36).substring(2, 8)}`;

    return await this.createDemoUser({
      userId,
      name: `${firstName} ${lastName}`,
      email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}@${department}.example.com`,
      roles: [role],
      scenario: `Random ${role} user from ${department} department`,
      type:
        role === 'user' ? 'basic' : role === 'creator' ? 'basic' : 'moderator',
      expectedBehavior: {
        'GET /demo/plain/basic': role === 'restricted' ? 'deny' : 'allow',
        'POST /demo/plain/advanced': ['moderator', 'dept-manager'].includes(
          role
        )
          ? 'allow'
          : 'deny',
      },
    });
  }

  /**
   * Create a demo user with comprehensive metadata
   */
  private async createDemoUser(params: {
    userId: string;
    name: string;
    email: string;
    roles: string[];
    scenario: string;
    type: 'basic' | 'admin' | 'moderator' | 'restricted';
    expectedBehavior: Record<string, 'allow' | 'deny'>;
  }): Promise<DemoUser> {
    const password = 'Demo123!'; // Same password for all demo users
    const hashedPassword = await bcrypt.hash(password, 10);

    // Calculate permissions from roles
    const permissions = this.calculateUserPermissions(params.roles);

    // Generate JWT tokens
    const accessToken = this.generateAccessToken(params.userId, params.roles);
    const refreshToken = this.generateRefreshToken(params.userId);

    return {
      userId: params.userId,
      name: params.name,
      email: params.email,
      password: hashedPassword,
      roles: params.roles,
      permissions,
      demo: {
        scenario: params.scenario,
        type: params.type,
        tokens: {
          access: accessToken,
          refresh: refreshToken,
        },
        expectedBehavior: params.expectedBehavior,
      },
    };
  }

  /**
   * Calculate user permissions from roles
   */
  private calculateUserPermissions(roleIds: string[]): string[] {
    const permissions = new Set<string>();

    for (const roleId of roleIds) {
      const role = DEMO_ROLES.find((r) => r.id === roleId);
      if (role) {
        role.permissions.forEach((permission) => permissions.add(permission));

        // Add parent role permissions
        if (role.parent) {
          const parentPermissions = this.calculateUserPermissions([
            role.parent,
          ]);
          parentPermissions.forEach((permission) =>
            permissions.add(permission)
          );
        }
      }
    }

    return Array.from(permissions);
  }

  /**
   * Generate access token for demo user
   */
  private generateAccessToken(userId: string, roles: string[]): string {
    const payload = {
      sub: userId,
      iss: this.config.JWT_ISSUER,
      aud: this.config.JWT_AUDIENCE,
      exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60, // 24 hours
      iat: Math.floor(Date.now() / 1000),
      roles,
      type: 'access',
    };

    return jwt.sign(payload, this.config.JWT_SECRET, { algorithm: 'HS256' });
  }

  /**
   * Generate refresh token for demo user
   */
  private generateRefreshToken(userId: string): string {
    const payload = {
      sub: userId,
      iss: this.config.JWT_ISSUER,
      aud: this.config.JWT_AUDIENCE,
      exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 days
      iat: Math.floor(Date.now() / 1000),
      type: 'refresh',
    };

    return jwt.sign(payload, this.config.JWT_SECRET, { algorithm: 'HS256' });
  }

  /**
   * Get demo users (sync method for convenience)
   */
  getDemoUsers(): DemoUser[] {
    // Return a basic set of predefined users for testing that match our JWT tokens
    return [
      {
        userId: 'user-basic-001',
        name: 'John User',
        email: 'john.user@example.com',
        password: 'Demo123!',
        roles: ['user'],
        permissions: [
          'user:profile:read',
          'user:profile:update',
          'content:create',
        ],
        demo: {
          scenario: 'Basic user with standard permissions',
          type: 'basic',
          tokens: {
            access: 'jwt-token',
            refresh: 'jwt-refresh-token',
          },
          expectedBehavior: {
            'GET /demo/plain/basic': 'allow',
            'POST /demo/plain/advanced': 'deny',
            'GET /demo/wildcard/admin': 'deny',
            'GET /demo/expression/simple': 'deny',
          },
        },
      },
      {
        userId: 'user-creator-001',
        name: 'Sarah Creator',
        email: 'sarah.creator@example.com',
        password: 'Demo123!',
        roles: ['creator'],
        permissions: [
          'user:profile:read',
          'user:profile:update',
          'content:create',
          'user:read',
        ],
        demo: {
          scenario: 'Content creator with enhanced permissions',
          type: 'basic',
          tokens: {
            access: 'jwt-token',
            refresh: 'jwt-refresh-token',
          },
          expectedBehavior: {
            'GET /demo/plain/basic': 'allow',
            'POST /demo/plain/advanced': 'deny',
            'GET /demo/wildcard/admin': 'deny',
            'GET /demo/expression/simple': 'allow',
          },
        },
      },
      {
        userId: 'user-moderator-001',
        name: 'Mike Moderator',
        email: 'mike.moderator@example.com',
        password: 'Demo123!',
        roles: ['moderator'],
        permissions: [
          'user:profile:read',
          'user:profile:update',
          'user:read',
          'content:create',
          'content:moderate',
          'user:update',
        ],
        demo: {
          scenario: 'Content moderator with user management permissions',
          type: 'moderator',
          tokens: {
            access: 'jwt-token',
            refresh: 'jwt-refresh-token',
          },
          expectedBehavior: {
            'GET /demo/plain/basic': 'allow',
            'POST /demo/plain/advanced': 'allow',
            'GET /demo/wildcard/admin': 'deny',
            'GET /demo/expression/simple': 'allow',
          },
        },
      },
      {
        userId: 'user-manager-001',
        name: 'Lisa Manager',
        email: 'lisa.manager@example.com',
        password: 'Demo123!',
        roles: ['dept-manager'],
        permissions: [
          'user:profile:read',
          'user:profile:update',
          'user:read',
          'user:create',
          'user:update',
          'dept:engineering:read',
        ],
        demo: {
          scenario: 'Department manager with hierarchical permissions',
          type: 'moderator',
          tokens: {
            access: 'jwt-token',
            refresh: 'jwt-refresh-token',
          },
          expectedBehavior: {
            'GET /demo/plain/basic': 'allow',
            'POST /demo/plain/advanced': 'allow',
            'GET /demo/wildcard/admin': 'deny',
            'GET /demo/wildcard/department': 'allow',
            'GET /demo/expression/simple': 'allow',
          },
        },
      },
      {
        userId: 'user-admin-001',
        name: 'Alice Administrator',
        email: 'alice.admin@example.com',
        password: 'Demo123!',
        roles: ['admin'],
        permissions: [
          'admin:users',
          'admin:system',
          'system:monitor',
          'system:backup',
          'dept:engineering:read',
          'dept:hr:read',
          'dept:finance:read',
          'content:moderate',
        ],
        demo: {
          scenario: 'System administrator with full permissions',
          type: 'admin',
          tokens: {
            access: 'jwt-token',
            refresh: 'jwt-refresh-token',
          },
          expectedBehavior: {
            'GET /demo/plain/basic': 'allow',
            'POST /demo/plain/advanced': 'allow',
            'GET /demo/wildcard/admin': 'allow',
            'GET /demo/wildcard/department': 'allow',
            'GET /demo/expression/simple': 'allow',
            'GET /demo/expression/complex': 'allow',
          },
        },
      },
      {
        userId: 'user-superadmin-001',
        name: 'Bob SuperAdmin',
        email: 'bob.superadmin@example.com',
        password: 'Demo123!',
        roles: ['superadmin'],
        permissions: [
          'admin:users',
          'admin:system',
          'admin:security',
          'system:monitor',
          'system:backup',
          'dept:engineering:read',
          'dept:hr:read',
          'dept:finance:read',
          'content:moderate',
          'user:delete',
        ],
        demo: {
          scenario: 'Super administrator with all permissions',
          type: 'admin',
          tokens: {
            access: 'jwt-token',
            refresh: 'jwt-refresh-token',
          },
          expectedBehavior: {
            'GET /demo/plain/basic': 'allow',
            'POST /demo/plain/advanced': 'allow',
            'GET /demo/wildcard/admin': 'allow',
            'GET /demo/wildcard/department': 'allow',
            'GET /demo/expression/simple': 'allow',
            'GET /demo/expression/complex': 'allow',
          },
        },
      },
      {
        userId: 'user-restricted-001',
        name: 'Charlie Restricted',
        email: 'charlie.restricted@example.com',
        password: 'Demo123!',
        roles: ['restricted'],
        permissions: ['user:profile:read'],
        demo: {
          scenario: 'Restricted user with minimal permissions for testing',
          type: 'restricted',
          tokens: {
            access: 'jwt-token',
            refresh: 'jwt-refresh-token',
          },
          expectedBehavior: {
            'GET /demo/plain/basic': 'deny',
            'POST /demo/plain/advanced': 'deny',
            'GET /demo/wildcard/admin': 'deny',
            'GET /demo/expression/simple': 'deny',
          },
        },
      },
    ];
  }
}

// ============================================================================
// SECURITY TEST SCENARIOS
// ============================================================================

/**
 * Generate security test scenarios for comprehensive testing
 */
export function generateSecurityTestScenarios(): SecurityTestScenario[] {
  return [
    // Authentication bypass attempts
    {
      id: 'auth-bypass-001',
      name: 'Missing Authorization Header',
      description:
        'Attempt to access protected endpoint without authorization header',
      category: 'authentication',
      steps: [
        {
          name: 'Request protected endpoint without auth',
          method: 'GET',
          path: '/demo/plain/basic',
          expect: { status: 401 },
        },
      ],
      expectedResults: {
        shouldSucceed: false,
        expectedStatus: 401,
        expectedMessage: 'Authentication required',
      },
    },

    {
      id: 'auth-bypass-002',
      name: 'Invalid Token Format',
      description: 'Attempt to use malformed JWT token',
      category: 'authentication',
      steps: [
        {
          name: 'Request with invalid token',
          method: 'GET',
          path: '/demo/plain/basic',
          headers: { Authorization: 'Bearer invalid-token-format' },
          expect: { status: 401 },
        },
      ],
      expectedResults: {
        shouldSucceed: false,
        expectedStatus: 401,
        expectedMessage: 'Invalid token',
      },
    },

    // Permission escalation attempts
    {
      id: 'perm-escalation-001',
      name: 'Admin Endpoint Access with User Token',
      description: 'Attempt to access admin endpoint with regular user token',
      category: 'authorization',
      steps: [
        {
          name: 'Request admin endpoint with user token',
          method: 'GET',
          path: '/demo/wildcard/admin',
          headers: { Authorization: 'Bearer user-token' },
          expect: { status: 403 },
        },
      ],
      expectedResults: {
        shouldSucceed: false,
        expectedStatus: 403,
        expectedMessage: 'Insufficient permissions',
      },
    },

    // Token manipulation attempts
    {
      id: 'token-manipulation-001',
      name: 'Modified Token Claims',
      description: 'Attempt to use token with modified claims',
      category: 'authentication',
      steps: [
        {
          name: 'Request with modified token',
          method: 'GET',
          path: '/demo/plain/basic',
          headers: { Authorization: 'Bearer modified-token' },
          expect: { status: 401 },
        },
      ],
      expectedResults: {
        shouldSucceed: false,
        expectedStatus: 401,
        expectedMessage: 'Invalid token signature',
      },
    },
  ];
}

// ============================================================================
// DYNAMIC TEST USER REGISTRATION
// ============================================================================

/**
 * Dynamic user registry for test isolation
 */
class TestUserRegistry {
  private testUsers = new Map<string, DemoUser>();
  private baseUserTemplates = new Map<string, DemoUser>();

  constructor() {
    // Pre-populate base user templates from static demo users
    this.initializeBaseTemplates();
  }

  /**
   * Initialize base user templates from static demo users
   */
  private initializeBaseTemplates() {
    const staticUsers = new DemoDataGenerator().getDemoUsers();
    staticUsers.forEach(user => {
      // Extract base user type from userId (e.g., "user-basic-001" -> "basic")
      const userType = this.extractUserType(user.userId);
      this.baseUserTemplates.set(userType, user);
    });
  }

  /**
   * Extract user type from user ID
   */
  private extractUserType(userId: string): 'basic' | 'admin' | 'moderator' | 'restricted' | 'superadmin' | 'manager' | 'creator' {
    const match = userId.match(/^user-(\w+)-\d+/);
    const extracted = match ? match[1] : 'basic';
    
    // Preserve specific user types to avoid losing permissions
    switch (extracted) {
      case 'admin': return 'admin';
      case 'superadmin': return 'superadmin'; // Keep superadmin separate
      case 'moderator': return 'moderator';  
      case 'restricted': return 'restricted';
      case 'manager': return 'manager'; // Keep manager separate
      case 'creator': return 'creator'; // Keep creator separate
      default: return 'basic';
    }
  }

  /**
   * Create or get a test user based on token data
   */
  createTestUser(tokenPayload: any): DemoUser | null {
    // Only create test users in development mode
    if (process.env.NODE_ENV !== 'development') {
      return null;
    }

    const { sub: userId, testRunId, roles, permissions, name, email } = tokenPayload;

    // Check if this is a test user (has test run ID and unique user ID)
    if (!testRunId || !userId.includes('-' + testRunId)) {
      return null;
    }

    // Return cached test user if already exists
    if (this.testUsers.has(userId)) {
      return this.testUsers.get(userId)!;
    }

    // Extract base user type from the user ID
    const baseUserId = userId.replace('-' + testRunId, '');
    const userType = this.extractUserType(baseUserId);
    const baseTemplate = this.baseUserTemplates.get(userType);

    if (!baseTemplate) {
      console.warn(`No base template found for user type: ${userType}`);
      return null;
    }

    // Create new test user using ONLY token data to preserve exact permissions
    const testUser: DemoUser = {
      ...baseTemplate,
      userId: userId,
      name: name || baseTemplate.name,
      email: email || baseTemplate.email,
      // Always use token data for roles and permissions to ensure accuracy
      roles: roles || [],
      permissions: permissions || [],
      demo: {
        ...baseTemplate.demo,
        testRunId: testRunId,
        type: userType,
        scenario: `Test user for ${testRunId}`,
        originalPermissions: permissions, // Store original for debugging
      } as any
    };

    // Cache the test user
    this.testUsers.set(userId, testUser);
    console.log(`🧪 Created test user: ${userId} (type: ${userType}, runId: ${testRunId})`);

    return testUser;
  }

  /**
   * Get a test user by ID
   */
  getTestUser(userId: string): DemoUser | undefined {
    return this.testUsers.get(userId);
  }

  /**
   * Get debug information about test users registry
   */
  getDebugInfo(): { count: number; userIds: string[] } {
    return {
      count: this.testUsers.size,
      userIds: Array.from(this.testUsers.keys())
    };
  }

  /**
   * Clear test users for a specific test run
   */
  clearTestRun(testRunId: string) {
    let cleared = 0;
    for (const [userId, user] of this.testUsers.entries()) {
      if ((user.demo as any)?.testRunId === testRunId) {
        this.testUsers.delete(userId);
        cleared++;
      }
    }
    if (cleared > 0) {
      console.log(`🧹 Cleared ${cleared} test users for run: ${testRunId}`);
    }
  }

  /**
   * Clear all test users
   */
  clearAllTestUsers() {
    const count = this.testUsers.size;
    this.testUsers.clear();
    if (count > 0) {
      console.log(`🧹 Cleared all ${count} test users`);
    }
  }

  /**
   * Generate test users for a specific test run
   * @param testRunId Test run ID to generate users for
   * @returns Number of users generated (pre-generation for token generation)
   */
  async generateTestUsers(testRunId: string): Promise<number> {
    // This method is called by the test data generation endpoint
    // We don't actually pre-generate users here since they are created dynamically
    // from tokens, but we can prepare the registry and return expected count

    console.log(`🧪 Preparing test user registry for run: ${testRunId}`);

    // The test script expects to create users based on the base templates
    // Return the count of base user types we support
    const userTypes = [
      'basic',
      'creator',
      'moderator',
      'manager',
      'admin',
      'superadmin',
      'restricted',
    ];
    const expectedUserCount = userTypes.length;

    console.log(
      `📊 Registry prepared for ${expectedUserCount} test user types in run: ${testRunId}`
    );

    return expectedUserCount;
  }

  /**
   * Clear test users - unified method for cleanup endpoint
   * @param testRunId Optional test run ID to clear specific run, or undefined to clear all
   * @returns Number of users cleared
   */
  async clearTestUsers(testRunId?: string): Promise<number> {
    if (testRunId) {
      // Clear specific test run
      let cleared = 0;
      for (const [userId, user] of this.testUsers.entries()) {
        if (
          (user.demo as DemoUser['demo'] & { testRunId?: string })
            ?.testRunId === testRunId
        ) {
          this.testUsers.delete(userId);
          cleared++;
        }
      }
      if (cleared > 0) {
        console.log(`🧹 Cleared ${cleared} test users for run: ${testRunId}`);
      }
      return cleared;
    } else {
      // Clear all test users
      const count = this.testUsers.size;
      this.testUsers.clear();
      if (count > 0) {
        console.log(`🧹 Cleared all ${count} test users`);
      }
      return count;
    }
  }
}

// Global test user registry
export const testUserRegistry = new TestUserRegistry();

// Export the TestUserRegistry class for direct access
export { TestUserRegistry };

// ============================================================================
// EXPORTS
// ============================================================================

export const demoDataGenerator = new DemoDataGenerator();

// Convenience functions for accessing demo data
export function getDemoUsers(): DemoUser[] {
  return demoDataGenerator.getDemoUsers();
}

export function getDemoUser(userId: string): DemoUser | undefined {
  return demoDataGenerator
    .getDemoUsers()
    .find((user: DemoUser) => user.userId === userId);
}

export function getDemoRoles(): Role[] {
  return DEMO_ROLES;
}

export function getDemoRole(roleId: string): Role | undefined {
  return DEMO_ROLES.find((role) => role.id === roleId);
}

export function getDemoPermissions(): Permission[] {
  return DEMO_PERMISSIONS;
}

export function getRolePermissions(roleId: string): string[] {
  const role = getDemoRole(roleId);
  return role ? (role.permissions as string[]) : [];
}
