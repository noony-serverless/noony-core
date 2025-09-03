# Noony Serverless Framework - Examples

This directory contains comprehensive, production-ready examples showcasing the Noony Serverless Framework capabilities. Each example is a standalone project with independent dependencies, demonstrating real-world usage patterns and best practices.

## 🚀 Quick Start

Choose an example based on your needs:

| Example | Complexity | Features | Best For |
|---------|------------|----------|----------|
| [hello-world-simple](./hello-world-simple/) | ⭐ Basic | GCP Functions, Zod validation, Error handling, Type safety | Learning fundamentals, Simple APIs, Getting started |
| [fastify-production-api](./fastify-production-api/) | ⭐⭐⭐ Advanced | Dual-mode development, JWT auth, CRUD operations, RBAC, Pagination, Audit logging | Production applications, Enterprise APIs, Complex systems |

## 📋 Prerequisites

Before running any example, ensure you have:

- **Node.js** v18+ and npm v9+
- **Google Cloud SDK** (for GCP Functions deployment)
- **TypeScript** knowledge (examples are fully typed)

## 🛠 Common Setup

1. **Clone and navigate to an example:**
   ```bash
   cd examples/hello-world-simple  # or fastify-production-api
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start development:**
   ```bash
   npm run dev
   ```

## 🏗 Framework Features Demonstrated

### Core Concepts
- ✅ **Handler System**: Middleware pipeline with lifecycle hooks
- ✅ **Type Safety**: Full TypeScript generics throughout
- ✅ **Error Handling**: Comprehensive error management
- ✅ **Validation**: Zod schema validation with type inference
- ✅ **Dependency Injection**: TypeDI container integration

### Production Features  
- ✅ **Authentication**: JWT token verification
- ✅ **Authorization**: Role-based access control
- ✅ **Rate Limiting**: Request throttling and abuse prevention
- ✅ **Security Headers**: Production security middleware
- ✅ **Audit Logging**: Request/response logging
- ✅ **Health Checks**: Service monitoring endpoints

### Development Experience
- ✅ **Dual Mode**: Fastify server + GCP Functions emulator
- ✅ **Hot Reload**: Automatic restart on code changes
- ✅ **Testing**: Unit and integration test examples
- ✅ **Documentation**: Comprehensive inline and README docs

## 🔧 Development Modes

Each example supports multiple development approaches:

### 1. **Fastify Server** (Fast Development)
```bash
npm run dev:fastify
# Server: http://localhost:3000
```
- Fast startup and hot reload
- Rich debugging experience
- Direct HTTP requests

### 2. **GCP Functions Emulator** (Production Parity)
```bash
npm run dev:functions  
# Server: http://localhost:8080
```
- Exact GCP Functions environment
- Test deployment behavior
- Validate function signatures

### 3. **Dual Mode** (Best of Both)
```bash
npm run dev:both
# Fastify: http://localhost:3000
# Functions: http://localhost:8080
```
- Run both modes simultaneously
- Compare behavior between environments
- Comprehensive testing

## 🚀 Deployment

Each example includes deployment guides for:

- **Google Cloud Functions**: Serverless deployment
- **Google Cloud Run**: Containerized deployment  
- **Kubernetes**: Self-managed deployment
- **Docker**: Containerized local deployment

## 📖 Learning Path

We recommend following this learning sequence:

### **Phase 1: Foundation** - [hello-world-simple](./hello-world-simple/)
Master the fundamentals with a simple but complete example:
- ✅ Basic Noony Handler and middleware patterns
- ✅ Comprehensive input validation with Zod schemas
- ✅ Type-safe development with TypeScript generics
- ✅ Error handling and response formatting
- ✅ Google Cloud Functions integration
- ✅ Environment configuration and deployment

### **Phase 2: Production** - [fastify-production-api](./fastify-production-api/)
Build enterprise-grade applications with advanced patterns:
- ✅ **Dual-Mode Development**: Fastify + GCP Functions
- ✅ **Authentication & Authorization**: JWT + RBAC
- ✅ **Complete CRUD API**: User management with advanced features
- ✅ **Production Patterns**: Service layers, dependency injection
- ✅ **Advanced Features**: Pagination, filtering, audit logging
- ✅ **Security Best Practices**: Password hashing, rate limiting
- ✅ **Monitoring & Health Checks**: Production-ready observability

### **Phase 3: Mastery**
After completing both examples, you'll be ready to:
- Build complex, production-ready serverless APIs
- Implement your own custom middleware
- Deploy to multiple cloud platforms
- Add advanced features like real-time capabilities
- Integrate with databases, caches, and message queues

## 🤝 Contributing

Found an issue or want to improve an example? See our [Contributing Guide](../README.md#contributing).

## 📚 Additional Resources

- [Framework Documentation](../README.md)
- [API Reference](../NOONY_COMPONENTS_REFERENCE.md)  
- [Complete Guide](../NOONY_COMPLETE_GUIDE.md)
- [Performance Guide](../PERFORMANCE.md)

---

**Next Steps**: Choose an example above and dive into its README for detailed setup instructions!