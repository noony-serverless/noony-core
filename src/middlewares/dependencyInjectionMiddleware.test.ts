import {
  dependencyInjection,
  DependencyInjectionMiddleware,
} from './dependencyInjectionMiddleware';
import { Context } from '../core/core';
import { ContainerInstance } from 'typedi';
import { containerPool, ServiceDefinition } from '../core/containerPool';

describe('DependencyInjectionMiddleware', () => {
  let context: Context;
  let services: ServiceDefinition[];

  beforeEach(() => {
    // Clear global container before each test
    containerPool.clear();

    context = {
      req: {},
      res: {},
      container: containerPool.createProxyContainer(),
      error: null,
      businessData: new Map(),
    } as unknown as Context;
    services = [
      { id: 'service1', value: { name: 'Service 1' } },
      { id: 'service2', value: { name: 'Service 2' } },
    ];
  });

  afterEach(() => {
    // Clean up after each test
    containerPool.clear();
  });

  it('sets services in local scope by default', async () => {
    const middleware = new DependencyInjectionMiddleware(services);

    await middleware.before(context);

    // Services should be in the local container
    expect(context.container?.get('service1')).toEqual({ name: 'Service 1' });
    expect(context.container?.get('service2')).toEqual({ name: 'Service 2' });
  });

  it('sets context.container to the Container instance', async () => {
    const middleware = new DependencyInjectionMiddleware(services);

    await middleware.before(context);

    expect(context.container).toBeInstanceOf(ContainerInstance);
  });

  it('does not throw if services array is empty', async () => {
    const middleware = new DependencyInjectionMiddleware([]);

    await expect(middleware.before(context)).resolves.not.toThrow();
  });

  it('registers services globally when scope is global', async () => {
    const middleware = new DependencyInjectionMiddleware(services, {
      scope: 'global',
    });

    await middleware.before(context);

    // Create a new container to verify global registration
    const newContainer = containerPool.createProxyContainer();
    expect(newContainer.get('service1')).toEqual({ name: 'Service 1' });
    expect(newContainer.get('service2')).toEqual({ name: 'Service 2' });
  });

  it('isolates local services between requests', async () => {
    const middleware = new DependencyInjectionMiddleware(services);

    // Request 1
    const context1 = {
      req: {},
      res: {},
      container: containerPool.createProxyContainer(),
      error: null,
      businessData: new Map(),
    } as unknown as Context;

    await middleware.before(context1);
    context1.container?.set('request-specific', 'request-1');

    // Request 2
    const context2 = {
      req: {},
      res: {},
      container: containerPool.createProxyContainer(),
      error: null,
      businessData: new Map(),
    } as unknown as Context;

    await middleware.before(context2);
    context2.container?.set('request-specific', 'request-2');

    // Verify isolation
    expect(context1.container?.get('request-specific')).toBe('request-1');
    expect(context2.container?.get('request-specific')).toBe('request-2');
  });
});

describe('dependencyInjection', () => {
  let context: Context;

  beforeEach(() => {
    containerPool.clear();

    context = {
      req: {},
      res: {},
      container: containerPool.createProxyContainer(),
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  afterEach(() => {
    containerPool.clear();
  });

  it('sets context.container to a new Container instance', async () => {
    const middleware = dependencyInjection();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.container).toBeInstanceOf(ContainerInstance);
  });

  it('sets services in local scope by default', async () => {
    const services: ServiceDefinition[] = [
      { id: 'config', value: { apiUrl: 'https://api.example.com' } },
    ];
    const middleware = dependencyInjection(services);

    if (middleware.before) {
      await middleware.before(context);
    }

    expect(context.container?.get('config')).toEqual({
      apiUrl: 'https://api.example.com',
    });
  });

  it('registers services globally when scope is global', async () => {
    const services: ServiceDefinition[] = [
      { id: 'logger', value: { log: () => 'logging' } },
    ];
    const middleware = dependencyInjection(services, { scope: 'global' });

    if (middleware.before) {
      await middleware.before(context);
    }

    // Create a new container to verify global registration
    const newContainer = containerPool.createProxyContainer();
    expect(newContainer.get('logger')).toEqual({ log: expect.any(Function) });
  });

  it('allows empty services array', async () => {
    const middleware = dependencyInjection([]);

    if (middleware.before) {
      await expect(middleware.before(context)).resolves.not.toThrow();
    }
  });

  it('defaults to local scope when no options provided', async () => {
    const services: ServiceDefinition[] = [{ id: 'temp', value: 'temp-value' }];
    const middleware = dependencyInjection(services);

    if (middleware.before) {
      await middleware.before(context);
    }

    // Verify it's in local scope (not visible to new containers)
    const newContainer = containerPool.createProxyContainer();
    expect(() => newContainer.get('temp')).toThrow();

    // But visible in the current context
    expect(context.container?.get('temp')).toBe('temp-value');
  });
});
