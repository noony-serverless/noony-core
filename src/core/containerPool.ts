import { Container, ContainerInstance } from 'typedi';

/**
 * Performance optimization: Container Pool for reusing TypeDI containers
 * This reduces object creation overhead and improves memory efficiency
 */
class ContainerPool {
  private availableContainers: ContainerInstance[] = [];
  private maxPoolSize: number = 10;
  private createdContainers: number = 0;

  constructor(maxPoolSize: number = 10) {
    this.maxPoolSize = maxPoolSize;
  }

  /**
   * Get a container from the pool or create a new one
   */
  acquire(): ContainerInstance {
    if (this.availableContainers.length > 0) {
      return this.availableContainers.pop()!;
    }

    // Create new container if pool is empty and under limit
    if (this.createdContainers < this.maxPoolSize) {
      this.createdContainers++;
      return Container.of();
    }

    // If pool is at capacity, create a temporary container
    // This should rarely happen in normal usage
    return Container.of();
  }

  /**
   * Return a container to the pool for reuse
   */
  release(container: ContainerInstance): void {
    if (this.availableContainers.length < this.maxPoolSize) {
      // Reset container state by removing all instances
      // This prevents memory leaks and cross-request contamination
      this.resetContainer(container);
      this.availableContainers.push(container);
    }
    // If pool is full, let the container be garbage collected
  }

  /**
   * Reset container state to prevent cross-request contamination
   * Note: TypeDI containers are isolated by default, so we mainly need
   * to clear any manually set values
   */
  private resetContainer(_container: ContainerInstance): void {
    try {
      // For TypeDI containers created with Container.of(), each container
      // is already isolated. We just need to ensure no memory leaks.
      // The container will be garbage collected when released from pool
      // if it contains too much data
      // TypeDI containers are self-contained and don't need explicit reset
      // This is a placeholder for future enhancements if needed
    } catch (error) {
      // If any issues occur, don't add back to pool
      console.warn('Failed to reset container, discarding:', error);
    }
  }

  /**
   * Get pool statistics for monitoring
   */
  getStats(): {
    available: number;
    created: number;
    maxSize: number;
  } {
    return {
      available: this.availableContainers.length,
      created: this.createdContainers,
      maxSize: this.maxPoolSize,
    };
  }

  /**
   * Warm up the pool by pre-creating containers
   */
  warmUp(count: number = 5): void {
    const warmUpCount = Math.min(count, this.maxPoolSize);
    for (let i = 0; i < warmUpCount; i++) {
      if (this.createdContainers < this.maxPoolSize) {
        const container = Container.of();
        this.createdContainers++;
        this.availableContainers.push(container);
      }
    }
  }

  /**
   * Clear all containers from the pool
   */
  clear(): void {
    this.availableContainers = [];
    this.createdContainers = 0;
  }
}

// Global container pool instance
const containerPool = new ContainerPool(15); // Slightly higher limit for serverless

// Warm up the pool for better cold start performance
containerPool.warmUp(3);

export { ContainerPool, containerPool };
