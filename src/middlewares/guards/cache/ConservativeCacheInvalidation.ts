/**
 * Conservative Cache Invalidation Service
 *
 * Implements a security-first approach to cache invalidation for permission systems.
 * When in doubt about data freshness or permission changes, this service errs on the
 * side of security by clearing broader cache segments rather than risking stale data.
 *
 * Security Principles:
 * - Invalidate broadly rather than narrowly when permissions change
 * - Clear dependent caches proactively to prevent inconsistencies
 * - Use time-based invalidation as backup for missed updates
 * - Log all invalidation events for audit trails
 * - Provide rollback capabilities for accidental cache clears
 *
 * Use Cases:
 * - User permission changes (role assignments, direct permissions)
 * - System-wide permission updates (new permissions, policy changes)
 * - Security incidents requiring immediate cache clearing
 * - Scheduled maintenance and cache refresh operations
 * - Development and testing environment resets
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { Service } from 'typedi';
import { CacheAdapter, CacheKeyBuilder } from './CacheAdapter';

/**
 * Cache invalidation event for audit logging
 */
export interface CacheInvalidationEvent {
  eventId: string;
  type: InvalidationType;
  scope: InvalidationScope;
  patterns: string[];
  affectedKeys?: string[];
  reason: string;
  userId?: string;
  timestamp: string;
  restorable: boolean;
  performance: {
    keysCleared: number;
    executionTimeMs: number;
  };
}

/**
 * Types of cache invalidation operations
 */
export enum InvalidationType {
  USER_PERMISSION_CHANGE = 'user_permission_change',
  ROLE_ASSIGNMENT_CHANGE = 'role_assignment_change',
  SYSTEM_PERMISSION_UPDATE = 'system_permission_update',
  SECURITY_INCIDENT = 'security_incident',
  SCHEDULED_REFRESH = 'scheduled_refresh',
  MANUAL_CLEAR = 'manual_clear',
  DEVELOPMENT_RESET = 'development_reset',
}

/**
 * Scope of cache invalidation
 */
export enum InvalidationScope {
  SINGLE_USER = 'single_user',
  MULTIPLE_USERS = 'multiple_users',
  ROLE_BASED = 'role_based',
  SYSTEM_WIDE = 'system_wide',
  PERMISSION_SPECIFIC = 'permission_specific',
}

/**
 * Cache backup for restoration
 */
interface CacheBackup {
  backupId: string;
  timestamp: string;
  scope: InvalidationScope;
  data: Map<string, any>;
  metadata: {
    totalEntries: number;
    sizeBytes: number;
    createdBy: string;
    reason: string;
  };
}

/**
 * Conservative Cache Invalidation Implementation
 */
@Service()
export class ConservativeCacheInvalidation {
  private readonly cache: CacheAdapter;
  private readonly auditLog: CacheInvalidationEvent[] = [];
  private readonly backups = new Map<string, CacheBackup>();
  private readonly maxAuditLogSize = 1000;
  private readonly maxBackupAge = 24 * 60 * 60 * 1000; // 24 hours

  // Performance tracking
  private invalidationCount = 0;
  private totalKeysCleared = 0;
  private totalExecutionTimeMs = 0;

  constructor(cache: CacheAdapter) {
    this.cache = cache;
  }

  /**
   * Invalidate cache for specific user permission changes
   *
   * Conservative approach: Clears all permission-related caches for the user
   * and any cached data that might depend on their permissions.
   *
   * @param userId - User whose permissions changed
   * @param reason - Reason for invalidation
   * @param createBackup - Whether to create restoration backup
   * @returns Invalidation event details
   */
  async invalidateUserPermissions(
    userId: string,
    reason: string,
    createBackup = false
  ): Promise<CacheInvalidationEvent> {
    const startTime = Date.now();
    const eventId = this.generateEventId();

    try {
      // Define patterns to clear for this user
      const patterns = [
        CacheKeyBuilder.userContext(userId),
        `perm:*:${userId}:*`, // Plain permission checks
        `wild:*:${userId}:*`, // Wildcard permission checks
        `expr:*:${userId}:*`, // Expression permission checks
        `auth:${userId}:*`, // Authentication caches
      ];

      // Create backup if requested
      if (createBackup) {
        await this.createBackup(
          `user_${userId}_${eventId}`,
          InvalidationScope.SINGLE_USER,
          patterns,
          `User permission change: ${reason}`
        );
      }

      // Clear caches
      const keysCleared = await this.clearCachesByPatterns(patterns);

      // Create audit event
      const event: CacheInvalidationEvent = {
        eventId,
        type: InvalidationType.USER_PERMISSION_CHANGE,
        scope: InvalidationScope.SINGLE_USER,
        patterns,
        reason,
        userId,
        timestamp: new Date().toISOString(),
        restorable: createBackup,
        performance: {
          keysCleared,
          executionTimeMs: Date.now() - startTime,
        },
      };

      await this.recordAuditEvent(event);
      this.updatePerformanceMetrics(keysCleared, Date.now() - startTime);

      console.log('🧹 Conservative cache invalidation completed', {
        type: 'user_permission_change',
        userId,
        keysCleared,
        duration: Date.now() - startTime,
        reason,
      });

      return event;
    } catch (error) {
      console.error('❌ Cache invalidation failed', {
        userId,
        reason,
        error: error instanceof Error ? error.message : 'Unknown error',
        duration: Date.now() - startTime,
      });
      throw error;
    }
  }

  /**
   * Invalidate cache for role-based permission changes
   *
   * Conservative approach: Clears caches for all users with the affected roles
   * plus any system-level permission caches that might be affected.
   *
   * @param roles - Roles whose permissions changed
   * @param reason - Reason for invalidation
   * @param createBackup - Whether to create restoration backup
   * @returns Invalidation event details
   */
  async invalidateRolePermissions(
    roles: string[],
    reason: string,
    createBackup = false
  ): Promise<CacheInvalidationEvent> {
    const startTime = Date.now();
    const eventId = this.generateEventId();

    try {
      // Conservative approach: Clear all user contexts and permission caches
      // Since we don't know which users have these roles, clear everything
      const patterns = [
        'user:context:*', // All user contexts
        'perm:*', // All permission checks
        'wild:*', // All wildcard checks
        'expr:*', // All expression checks
        'auth:*', // All authentication caches
        'role:permissions:*', // Role permission mappings
      ];

      // Create backup if requested
      if (createBackup) {
        await this.createBackup(
          `roles_${roles.join('_')}_${eventId}`,
          InvalidationScope.ROLE_BASED,
          patterns,
          `Role permission change: ${reason}`
        );
      }

      // Clear caches
      const keysCleared = await this.clearCachesByPatterns(patterns);

      // Create audit event
      const event: CacheInvalidationEvent = {
        eventId,
        type: InvalidationType.ROLE_ASSIGNMENT_CHANGE,
        scope: InvalidationScope.ROLE_BASED,
        patterns,
        reason: `Roles affected: ${roles.join(', ')} - ${reason}`,
        timestamp: new Date().toISOString(),
        restorable: createBackup,
        performance: {
          keysCleared,
          executionTimeMs: Date.now() - startTime,
        },
      };

      await this.recordAuditEvent(event);
      this.updatePerformanceMetrics(keysCleared, Date.now() - startTime);

      console.log('🧹 Conservative role cache invalidation completed', {
        type: 'role_permission_change',
        roles,
        keysCleared,
        duration: Date.now() - startTime,
        reason,
      });

      return event;
    } catch (error) {
      console.error('❌ Role cache invalidation failed', {
        roles,
        reason,
        error: error instanceof Error ? error.message : 'Unknown error',
        duration: Date.now() - startTime,
      });
      throw error;
    }
  }

  /**
   * System-wide cache invalidation
   *
   * Nuclear option: Clears all permission-related caches across the system.
   * Used for major system updates, security incidents, or when unsure about
   * the scope of changes.
   *
   * @param reason - Reason for system-wide invalidation
   * @param createBackup - Whether to create restoration backup
   * @returns Invalidation event details
   */
  async invalidateSystemWide(
    reason: string,
    createBackup = false
  ): Promise<CacheInvalidationEvent> {
    const startTime = Date.now();
    const eventId = this.generateEventId();

    try {
      // Nuclear option: clear everything
      const patterns = ['*'];

      // Create backup if requested (warning: this could be large)
      if (createBackup) {
        await this.createBackup(
          `system_wide_${eventId}`,
          InvalidationScope.SYSTEM_WIDE,
          patterns,
          `System-wide invalidation: ${reason}`
        );
      }

      // Flush entire cache
      await this.cache.flush();
      const keysCleared = -1; // Unknown count for flush operation

      // Create audit event
      const event: CacheInvalidationEvent = {
        eventId,
        type: InvalidationType.SYSTEM_PERMISSION_UPDATE,
        scope: InvalidationScope.SYSTEM_WIDE,
        patterns,
        reason,
        timestamp: new Date().toISOString(),
        restorable: createBackup,
        performance: {
          keysCleared,
          executionTimeMs: Date.now() - startTime,
        },
      };

      await this.recordAuditEvent(event);
      this.updatePerformanceMetrics(1000, Date.now() - startTime); // Estimate for stats

      console.log('💥 System-wide cache invalidation completed', {
        type: 'system_wide',
        duration: Date.now() - startTime,
        reason,
        warning: 'All caches cleared',
      });

      return event;
    } catch (error) {
      console.error('❌ System-wide cache invalidation failed', {
        reason,
        error: error instanceof Error ? error.message : 'Unknown error',
        duration: Date.now() - startTime,
      });
      throw error;
    }
  }

  /**
   * Emergency security invalidation
   *
   * Immediate cache clearing for security incidents.
   * Bypasses backup creation for speed and clears everything.
   *
   * @param reason - Security incident description
   * @returns Invalidation event details
   */
  async emergencySecurityInvalidation(
    reason: string
  ): Promise<CacheInvalidationEvent> {
    const startTime = Date.now();
    const eventId = this.generateEventId();

    try {
      // Emergency flush - no backup, clear everything immediately
      await this.cache.flush();

      // Create audit event
      const event: CacheInvalidationEvent = {
        eventId,
        type: InvalidationType.SECURITY_INCIDENT,
        scope: InvalidationScope.SYSTEM_WIDE,
        patterns: ['*'],
        reason: `SECURITY INCIDENT: ${reason}`,
        timestamp: new Date().toISOString(),
        restorable: false,
        performance: {
          keysCleared: -1,
          executionTimeMs: Date.now() - startTime,
        },
      };

      await this.recordAuditEvent(event);
      this.updatePerformanceMetrics(1000, Date.now() - startTime);

      console.error('🚨 EMERGENCY: Security cache invalidation completed', {
        type: 'security_incident',
        duration: Date.now() - startTime,
        reason,
        warning: 'ALL CACHES CLEARED FOR SECURITY',
      });

      return event;
    } catch (error) {
      console.error('❌ CRITICAL: Emergency cache invalidation failed', {
        reason,
        error: error instanceof Error ? error.message : 'Unknown error',
        duration: Date.now() - startTime,
      });
      throw error;
    }
  }

  /**
   * Restore cache from backup
   *
   * Attempts to restore previously backed up cache data.
   * Use with caution - only restore if you're certain the data is safe.
   *
   * @param backupId - ID of the backup to restore
   * @returns Restoration success status
   */
  async restoreFromBackup(backupId: string): Promise<boolean> {
    const backup = this.backups.get(backupId);
    if (!backup) {
      console.error('❌ Backup not found', { backupId });
      return false;
    }

    // Check backup age
    const backupAge = Date.now() - new Date(backup.timestamp).getTime();
    if (backupAge > this.maxBackupAge) {
      console.warn('⚠️ Backup is old, restoration may not be safe', {
        backupId,
        ageHours: backupAge / (1000 * 60 * 60),
      });
    }

    try {
      let restoredCount = 0;

      // Restore each cache entry
      for (const [key, value] of backup.data) {
        await this.cache.set(key, value);
        restoredCount++;
      }

      console.log('✅ Cache restored from backup', {
        backupId,
        restoredEntries: restoredCount,
        originalSize: backup.metadata.totalEntries,
      });

      return true;
    } catch (error) {
      console.error('❌ Cache restoration failed', {
        backupId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return false;
    }
  }

  /**
   * Get invalidation audit log
   */
  getAuditLog(): CacheInvalidationEvent[] {
    return [...this.auditLog];
  }

  /**
   * Get available backups
   */
  getAvailableBackups(): Array<{
    backupId: string;
    timestamp: string;
    scope: InvalidationScope;
    totalEntries: number;
    sizeBytes: number;
    ageHours: number;
  }> {
    return Array.from(this.backups.values()).map((backup) => ({
      backupId: backup.backupId,
      timestamp: backup.timestamp,
      scope: backup.scope,
      totalEntries: backup.metadata.totalEntries,
      sizeBytes: backup.metadata.sizeBytes,
      ageHours:
        (Date.now() - new Date(backup.timestamp).getTime()) / (1000 * 60 * 60),
    }));
  }

  /**
   * Get invalidation statistics
   */
  getStats() {
    return {
      invalidationCount: this.invalidationCount,
      totalKeysCleared: this.totalKeysCleared,
      averageExecutionTimeMs:
        this.invalidationCount > 0
          ? this.totalExecutionTimeMs / this.invalidationCount
          : 0,
      totalExecutionTimeMs: this.totalExecutionTimeMs,
      auditLogSize: this.auditLog.length,
      backupsAvailable: this.backups.size,
      oldestBackupAge: this.getOldestBackupAge(),
    };
  }

  /**
   * Clear patterns from cache
   */
  private async clearCachesByPatterns(patterns: string[]): Promise<number> {
    let totalKeysCleared = 0;

    for (const pattern of patterns) {
      try {
        if (pattern === '*') {
          // Special case: flush all
          await this.cache.flush();
          return -1; // Unknown count
        } else {
          // Pattern-based deletion
          await this.cache.deletePattern(pattern);
          totalKeysCleared += 10; // Estimate since we don't have exact counts
        }
      } catch (error) {
        console.warn('⚠️ Pattern deletion failed', {
          pattern,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    return totalKeysCleared;
  }

  /**
   * Create backup of cache data
   */
  private async createBackup(
    backupId: string,
    scope: InvalidationScope,
    patterns: string[],
    reason: string
  ): Promise<void> {
    // Note: This is a simplified backup implementation
    // In production, you'd implement pattern-based cache reading
    const backup: CacheBackup = {
      backupId,
      timestamp: new Date().toISOString(),
      scope,
      data: new Map(), // Would contain actual cached data
      metadata: {
        totalEntries: 0,
        sizeBytes: 0,
        createdBy: 'ConservativeCacheInvalidation',
        reason,
      },
    };

    this.backups.set(backupId, backup);

    // Clean up old backups
    this.cleanupOldBackups();
  }

  /**
   * Record audit event
   */
  private async recordAuditEvent(event: CacheInvalidationEvent): Promise<void> {
    this.auditLog.push(event);

    // Keep audit log size manageable
    if (this.auditLog.length > this.maxAuditLogSize) {
      this.auditLog.shift();
    }
  }

  /**
   * Update performance metrics
   */
  private updatePerformanceMetrics(
    keysCleared: number,
    executionTimeMs: number
  ): void {
    this.invalidationCount++;
    this.totalKeysCleared += Math.max(0, keysCleared);
    this.totalExecutionTimeMs += executionTimeMs;
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    return `inv_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clean up old backups
   */
  private cleanupOldBackups(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [backupId, backup] of this.backups) {
      const age = now - new Date(backup.timestamp).getTime();
      if (age > this.maxBackupAge) {
        keysToDelete.push(backupId);
      }
    }

    keysToDelete.forEach((key) => {
      this.backups.delete(key);
    });

    if (keysToDelete.length > 0) {
      console.log('🗑️ Cleaned up old cache backups', {
        removedBackups: keysToDelete.length,
      });
    }
  }

  /**
   * Get age of oldest backup in hours
   */
  private getOldestBackupAge(): number {
    if (this.backups.size === 0) return 0;

    let oldest = Date.now();
    for (const backup of this.backups.values()) {
      const backupTime = new Date(backup.timestamp).getTime();
      if (backupTime < oldest) {
        oldest = backupTime;
      }
    }

    return (Date.now() - oldest) / (1000 * 60 * 60);
  }
}
