import {
  dependencyInjection,
  DependencyInjectionMiddleware,
} from './dependencyInjectionMiddleware';
import { Context } from '../core/core';
import { Container, ContainerInstance } from 'typedi';

describe('DependencyInjectionMiddleware', () => {
  let context: Context;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let services: { id: any; value: any }[];

  beforeEach(() => {
    context = {
      req: {},
      res: {},
      container: Container.of(),
      error: null,
      businessData: new Map(),
    } as unknown as Context;
    services = [
      { id: 'service1', value: { name: 'Service 1' } },
      { id: 'service2', value: { name: 'Service 2' } },
    ];
  });

  it('sets services in the container', async () => {
    const middleware = new DependencyInjectionMiddleware(services);

    await middleware.before(context);

    expect(Container.get('service1')).toEqual({ name: 'Service 1' });
    expect(Container.get('service2')).toEqual({ name: 'Service 2' });
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

  it('overwrites existing services in the container', async () => {
    Container.set('service1', { name: 'Old Service 1' });
    const middleware = new DependencyInjectionMiddleware(services);

    await middleware.before(context);

    expect(Container.get('service1')).toEqual({ name: 'Service 1' });
  });
});

describe('dependencyInjection', () => {
  let context: Context;

  beforeEach(() => {
    context = {
      req: {},
      res: {},
      container: Container.of(),
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  it('sets context.container to a new Container instance', async () => {
    const middleware = dependencyInjection();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.container).toBeInstanceOf(ContainerInstance);
  });

  it('uses the existing scope container for each request', async () => {
    const middleware = dependencyInjection();
    if (middleware.before) {
      await middleware.before(context);
    }
    const firstContainer = context.container;

    if (middleware.before) {
      await middleware.before(context);
    }
    const secondContainer = context.container;

    expect(firstContainer).toBe(secondContainer);
    expect(firstContainer).toBeInstanceOf(ContainerInstance);
    expect(secondContainer).toBeInstanceOf(ContainerInstance);
  });
});
