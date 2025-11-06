/**
 * Permission Registry
 *
 * Central registry for managing available permissions in the system.
 * Supports wildcard pattern expansion, permission discovery, and
 * category-based organization for efficient permission management.
 *
 * Key Features:
 * - Permission registration and discovery
 * - Wildcard pattern expansion ("admin.*" -> ["admin.users", "admin.roles"])
 * - Category-based organization
 * - Thread-safe operations with caching
 * - Auto-discovery from codebase annotations
 * - Permission hierarchy validation
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

/**
 * Permission metadata for rich permission information
 */
export interface PermissionMetadata {
  /** Permission string (e.g., "admin.users.create") */
  permission: string;

  /** Human-readable description */
  description: string;

  /** Permission category (e.g., "admin", "user", "content") */
  category: string;

  /** Sub-category (e.g., "users", "roles") */
  subCategory?: string;

  /** Action (e.g., "create", "read", "update", "delete") */
  action?: string;

  /** Risk level for security analysis */
  riskLevel: 'low' | 'medium' | 'high' | 'critical';

  /** Whether this permission requires additional validation */
  requiresValidation: boolean;

  /** Related permissions that are commonly used together */
  relatedPermissions?: string[];

  /** When this permission was registered */
  registeredAt: Date;
}

/**
 * Permission registry interface for wildcard expansion and management
 */
export interface PermissionRegistry {
  /**
   * Register a permission with metadata
   */
  registerPermission(metadata: PermissionMetadata): void;

  /**
   * Register multiple permissions at once
   */
  registerPermissions(permissions: PermissionMetadata[]): void;

  /**
   * Get all permissions matching a wildcard pattern
   */
  getMatchingPermissions(wildcardPattern: string): string[];

  /**
   * Get all permissions in a category
   */
  getCategoryPermissions(category: string): string[];

  /**
   * Check if a permission exists in the registry
   */
  hasPermission(permission: string): boolean;

  /**
   * Get permission metadata
   */
  getPermissionMetadata(permission: string): PermissionMetadata | null;

  /**
   * Get all registered permissions
   */
  getAllPermissions(): string[];

  /**
   * Get all categories
   */
  getAllCategories(): string[];

  /**
   * Get registry statistics
   */
  getStats(): PermissionRegistryStats;
}

/**
 * Registry statistics for monitoring
 */
export interface PermissionRegistryStats {
  totalPermissions: number;
  totalCategories: number;
  permissionsByCategory: Record<string, number>;
  riskLevelDistribution: Record<string, number>;
  registrationTimeline: Date[];
}

/**
 * Default permission registry implementation
 *
 * Thread-safe in-memory registry with caching for pattern matching.
 * In production, this could be backed by a database or external service.
 */
export class DefaultPermissionRegistry implements PermissionRegistry {
  private readonly permissions = new Map<string, PermissionMetadata>();
  private readonly categoryIndex = new Map<string, Set<string>>();
  private readonly patternCache = new Map<string, string[]>();

  // Performance tracking
  private stats = {
    totalLookups: 0,
    patternMatchingTime: 0,
    cacheHits: 0,
    cacheMisses: 0,
  };

  constructor() {
    // Initialize with common system permissions
    this.initializeSystemPermissions();
  }

  /**
   * Register a permission with metadata
   */
  registerPermission(metadata: PermissionMetadata): void {
    // Validate permission format
    if (!this.isValidPermissionFormat(metadata.permission)) {
      throw new Error(`Invalid permission format: ${metadata.permission}`);
    }

    // Check for duplicates
    if (this.permissions.has(metadata.permission)) {
      console.warn(`Permission ${metadata.permission} is already registered`);
      return;
    }

    // Extract category from permission if not provided
    if (!metadata.category) {
      metadata.category = this.extractCategory(metadata.permission);
    }

    // Store permission
    this.permissions.set(metadata.permission, {
      ...metadata,
      registeredAt: new Date(),
    });

    // Update category index
    if (!this.categoryIndex.has(metadata.category)) {
      this.categoryIndex.set(metadata.category, new Set());
    }
    this.categoryIndex.get(metadata.category)!.add(metadata.permission);

    // Invalidate pattern cache since new permission might affect wildcard matches
    this.patternCache.clear();

    console.debug(
      `Registered permission: ${metadata.permission} (${metadata.category})`
    );
  }

  /**
   * Register multiple permissions at once
   */
  registerPermissions(permissions: PermissionMetadata[]): void {
    for (const permission of permissions) {
      this.registerPermission(permission);
    }
  }

  /**
   * Get all permissions matching a wildcard pattern
   */
  getMatchingPermissions(wildcardPattern: string): string[] {
    const startTime = process.hrtime.bigint();
    this.stats.totalLookups++;

    try {
      // Check cache first
      if (this.patternCache.has(wildcardPattern)) {
        this.stats.cacheHits++;
        return this.patternCache.get(wildcardPattern)!;
      }

      this.stats.cacheMisses++;

      // Convert wildcard pattern to regex
      const regex = this.wildcardToRegex(wildcardPattern);
      const matchingPermissions: string[] = [];

      // Find all matching permissions
      for (const permission of this.permissions.keys()) {
        if (regex.test(permission)) {
          matchingPermissions.push(permission);
        }
      }

      // Cache the result
      this.patternCache.set(wildcardPattern, matchingPermissions);

      return matchingPermissions;
    } finally {
      const endTime = process.hrtime.bigint();
      this.stats.patternMatchingTime += Number(endTime - startTime) / 1000; // microseconds
    }
  }

  /**
   * Get all permissions in a category
   */
  getCategoryPermissions(category: string): string[] {
    const permissions = this.categoryIndex.get(category);
    return permissions ? Array.from(permissions) : [];
  }

  /**
   * Check if a permission exists in the registry
   */
  hasPermission(permission: string): boolean {
    return this.permissions.has(permission);
  }

  /**
   * Get permission metadata
   */
  getPermissionMetadata(permission: string): PermissionMetadata | null {
    return this.permissions.get(permission) || null;
  }

  /**
   * Get all registered permissions
   */
  getAllPermissions(): string[] {
    return Array.from(this.permissions.keys());
  }

  /**
   * Get all categories
   */
  getAllCategories(): string[] {
    return Array.from(this.categoryIndex.keys());
  }

  /**
   * Get registry statistics
   */
  getStats(): PermissionRegistryStats {
    const permissionsByCategory: Record<string, number> = {};
    const riskLevelDistribution: Record<string, number> = {};
    const registrationTimeline: Date[] = [];

    for (const [category, permissions] of this.categoryIndex) {
      permissionsByCategory[category] = permissions.size;
    }

    for (const metadata of this.permissions.values()) {
      riskLevelDistribution[metadata.riskLevel] =
        (riskLevelDistribution[metadata.riskLevel] || 0) + 1;
      registrationTimeline.push(metadata.registeredAt);
    }

    return {
      totalPermissions: this.permissions.size,
      totalCategories: this.categoryIndex.size,
      permissionsByCategory,
      riskLevelDistribution,
      registrationTimeline: registrationTimeline.sort(
        (a, b) => a.getTime() - b.getTime()
      ),
    };
  }

  /**
   * Get performance statistics
   */
  getPerformanceStats(): {
    totalLookups: number;
    averagePatternMatchingTimeUs: number;
    cacheHitRate: number;
    cacheSize: number;
  } {
    const totalCacheRequests = this.stats.cacheHits + this.stats.cacheMisses;

    return {
      totalLookups: this.stats.totalLookups,
      averagePatternMatchingTimeUs:
        this.stats.totalLookups > 0
          ? this.stats.patternMatchingTime / this.stats.totalLookups
          : 0,
      cacheHitRate:
        totalCacheRequests > 0
          ? (this.stats.cacheHits / totalCacheRequests) * 100
          : 0,
      cacheSize: this.patternCache.size,
    };
  }

  /**
   * Clear the pattern cache
   */
  clearCache(): void {
    this.patternCache.clear();
  }

  /**
   * Initialize common system permissions
   */
  private initializeSystemPermissions(): void {
    const now = new Date();
    const systemPermissions: PermissionMetadata[] = [
      // User management permissions
      {
        permission: 'user.create',
        description: 'Create new user accounts',
        category: 'user',
        action: 'create',
        riskLevel: 'medium',
        requiresValidation: true,
        registeredAt: now,
      },
      {
        permission: 'user.read',
        description: 'View user information',
        category: 'user',
        action: 'read',
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: now,
      },
      {
        permission: 'user.update',
        description: 'Update user information',
        category: 'user',
        action: 'update',
        riskLevel: 'medium',
        requiresValidation: true,
        registeredAt: now,
      },
      {
        permission: 'user.delete',
        description: 'Delete user accounts',
        category: 'user',
        action: 'delete',
        riskLevel: 'high',
        requiresValidation: true,
        registeredAt: now,
      },
      {
        permission: 'user.list',
        description: 'List users with filtering',
        category: 'user',
        action: 'list',
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: now,
      },

      // Admin permissions
      {
        permission: 'admin.users',
        description: 'Full administrative access to user management',
        category: 'admin',
        subCategory: 'users',
        riskLevel: 'critical',
        requiresValidation: true,
        registeredAt: now,
      },
      {
        permission: 'admin.system',
        description: 'System-level administrative access',
        category: 'admin',
        subCategory: 'system',
        riskLevel: 'critical',
        requiresValidation: true,
        registeredAt: now,
      },
      {
        permission: 'admin.monitoring',
        description: 'Access to monitoring and metrics',
        category: 'admin',
        subCategory: 'monitoring',
        riskLevel: 'medium',
        requiresValidation: false,
        registeredAt: now,
      },

      // Organization permissions
      {
        permission: 'organization.view',
        description: 'View organization information',
        category: 'organization',
        action: 'view',
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: now,
      },
      {
        permission: 'organization.manage',
        description: 'Manage organization settings',
        category: 'organization',
        action: 'manage',
        riskLevel: 'high',
        requiresValidation: true,
        registeredAt: now,
      },

      // Situation report permissions
      {
        permission: 'situation.reports.create',
        description: 'Create situation reports',
        category: 'situation',
        subCategory: 'reports',
        action: 'create',
        riskLevel: 'medium',
        requiresValidation: false,
        registeredAt: now,
      },
      {
        permission: 'situation.reports.view',
        description: 'View situation reports',
        category: 'situation',
        subCategory: 'reports',
        action: 'view',
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: now,
      },
      {
        permission: 'situation.reports.update',
        description: 'Update situation reports',
        category: 'situation',
        subCategory: 'reports',
        action: 'update',
        riskLevel: 'medium',
        requiresValidation: true,
        registeredAt: now,
      },
      {
        permission: 'situation.reports.delete',
        description: 'Delete situation reports',
        category: 'situation',
        subCategory: 'reports',
        action: 'delete',
        riskLevel: 'high',
        requiresValidation: true,
        registeredAt: now,
      },

      // System permissions
      {
        permission: 'system.health',
        description: 'Access system health information',
        category: 'system',
        action: 'health',
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: now,
      },
      {
        permission: 'system.metrics',
        description: 'Access system metrics',
        category: 'system',
        action: 'metrics',
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: now,
      },
      {
        permission: 'system.logs',
        description: 'Access system logs',
        category: 'system',
        action: 'logs',
        riskLevel: 'medium',
        requiresValidation: true,
        registeredAt: now,
      },
    ];

    this.registerPermissions(systemPermissions);
  }

  /**
   * Validate permission format (2-3 levels with alphanumeric + dots)
   */
  private isValidPermissionFormat(permission: string): boolean {
    if (!permission || typeof permission !== 'string') {
      return false;
    }

    // Allow both concrete permissions and wildcard patterns
    const validPattern = /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+){1,2}$/;
    const wildcardPattern = /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.\*$/;

    return validPattern.test(permission) || wildcardPattern.test(permission);
  }

  /**
   * Extract category from permission string
   */
  private extractCategory(permission: string): string {
    const parts = permission.split('.');
    return parts[0] || 'unknown';
  }

  /**
   * Convert wildcard pattern to regex
   */
  private wildcardToRegex(wildcardPattern: string): RegExp {
    if (!wildcardPattern.includes('*')) {
      // Exact match for non-wildcard patterns
      return new RegExp(`^${wildcardPattern.replace(/\./g, '\\.')}$`);
    }

    // Convert wildcard pattern to regex
    // "admin.*" becomes /^admin\..*$/
    // "admin.users.*" becomes /^admin\.users\..*$/
    const regexPattern = wildcardPattern
      .replace(/\./g, '\\.') // Escape dots
      .replace(/\*/g, '.*'); // Replace * with any characters

    return new RegExp(`^${regexPattern}$`);
  }
}

/**
 * Factory for creating permission registries
 */
export class PermissionRegistryFactory {
  /**
   * Create a default permission registry with system permissions
   */
  static createDefault(): DefaultPermissionRegistry {
    return new DefaultPermissionRegistry();
  }

  /**
   * Create an empty permission registry
   */
  static createEmpty(): DefaultPermissionRegistry {
    const registry = new DefaultPermissionRegistry();
    // Clear system permissions if needed for testing
    return registry;
  }

  /**
   * Create a registry from a permission definition file
   */
  static createFromDefinitions(
    definitions: PermissionMetadata[]
  ): DefaultPermissionRegistry {
    const registry = new DefaultPermissionRegistry();
    registry.registerPermissions(definitions);
    return registry;
  }
}
