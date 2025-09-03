# Hello World Simple - Setup Guide

This guide provides detailed step-by-step instructions for setting up the Hello World Simple example, from initial installation to your first successful API call.

## 📋 Prerequisites Checklist

Before starting, ensure you have the following installed and configured:

### Required Software

- [ ] **Node.js v18+** 
  ```bash
  node --version  # Should show v18.x.x or higher
  ```

- [ ] **npm v9+** 
  ```bash
  npm --version   # Should show v9.x.x or higher
  ```

- [ ] **Git** (for cloning the repository)
  ```bash
  git --version   # Should show version information
  ```

### Optional but Recommended

- [ ] **Google Cloud SDK** (for deployment)
  ```bash
  gcloud --version  # Should show version information
  ```

- [ ] **VS Code** with TypeScript extension (for development)
- [ ] **curl** or **Postman** (for API testing)

## 🚀 Step-by-Step Setup

### 1. Get the Code

If you're starting from the Noony repository:

```bash
# Clone the repository (if you haven't already)
git clone https://github.com/noony-serverless/noony-core.git
cd noony-core

# Navigate to the example
cd examples/hello-world-simple
```

If you're creating a new project based on this example:

```bash
# Create new directory
mkdir my-noony-hello-world
cd my-noony-hello-world

# Copy the example files
# (You'll need to copy the files manually or download them)
```

### 2. Install Dependencies

```bash
# Install all required dependencies
npm install

# Verify installation
npm list --depth=0
```

**Expected output should include:**
- `@noony-serverless/core`
- `@google-cloud/functions-framework`
- `zod`
- Development dependencies (TypeScript, ESLint, etc.)

### 3. Environment Configuration

```bash
# Copy the environment template
cp .env.example .env

# View the default configuration
cat .env
```

**Edit `.env` file if needed:**
```bash
# Open in your preferred editor
nano .env
# or
code .env
```

**Key settings to consider:**
- `DEBUG=true` - Enable detailed logging (recommended for learning)
- `PORT=8080` - Change if port 8080 is in use
- `DEFAULT_GREETING=Hello` - Customize the default greeting

### 4. Build and Validate

```bash
# Compile TypeScript to check for errors
npm run build

# Should create a 'dist' directory with compiled JavaScript
ls -la dist/
```

**Expected output:**
- `dist/index.js` - Compiled handler
- `dist/types.js` - Compiled type definitions
- `dist/index.d.ts` - Type declaration files

### 5. Start Development Server

```bash
# Start with hot reload enabled
npm run dev
```

**You should see output like:**
```
Serving function...
Function: helloWorld
Signature type: http
URL: http://localhost:8080/
```

**The server is ready when you see:**
- No error messages
- Port number displayed
- "Serving function..." message

### 6. Test Basic Functionality

Open a new terminal and test the API:

```bash
# Basic health check (should work immediately)
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"name": "World"}'
```

**Expected response:**
```json
{
  "success": true,
  "payload": {
    "message": "Hello, World!",
    "timestamp": "2024-01-15T10:30:45.123Z"
  },
  "timestamp": "2024-01-15T10:30:45.125Z"
}
```

## 🔧 Troubleshooting Common Setup Issues

### Issue: "Cannot find module '@noony-serverless/core'"

**Cause**: The core Noony package isn't properly linked or installed.

**Solution**:
```bash
# If running from the repository examples directory
cd ../../  # Go to root
npm run build  # Build the core library
cd examples/hello-world-simple
npm install  # Reinstall dependencies
```

### Issue: "Port 8080 is already in use"

**Cause**: Another service is using the default port.

**Solution**:
```bash
# Option 1: Change port in .env file
echo "PORT=8081" >> .env

# Option 2: Specify port directly
npx functions-framework --target=helloWorld --source=src --port=8081
```

### Issue: "Function not found: helloWorld"

**Cause**: TypeScript hasn't been compiled or there's an export issue.

**Solution**:
```bash
# Ensure TypeScript compiles without errors
npm run build

# Check for compilation errors
npx tsc --noEmit

# Verify the export exists
grep -n "export.*helloWorld" src/index.ts
```

### Issue: Permission denied during deployment

**Cause**: Google Cloud SDK not properly authenticated.

**Solution**:
```bash
# Authenticate with Google Cloud
gcloud auth login

# Set your project
gcloud config set project YOUR_PROJECT_ID

# Verify authentication
gcloud auth list
```

### Issue: TypeScript compilation errors

**Cause**: Strict TypeScript settings or missing type definitions.

**Solution**:
```bash
# Check for specific errors
npm run build

# Common fixes:
# 1. Update TypeScript version
npm update typescript

# 2. Check tsconfig.json settings
cat tsconfig.json

# 3. Verify all imports are correct
grep -n "import.*from" src/*.ts
```

## 📝 Verification Checklist

Once setup is complete, verify everything works:

### Basic Functionality
- [ ] Server starts without errors: `npm run dev`
- [ ] Basic request works: `curl -X POST http://localhost:8080 -d '{"name":"Test"}' -H 'Content-Type: application/json'`
- [ ] Response has correct structure with `success: true`
- [ ] TypeScript compiles: `npm run build`
- [ ] Linting passes: `npm run lint`

### Advanced Features
- [ ] Custom greeting works: `{"name":"Alice","greeting":"Hi"}`
- [ ] Timestamp toggling works: `{"name":"Bob","includeTimestamp":false}`
- [ ] Language specification works: `{"name":"María","language":"es"}`
- [ ] Error handling works: Send request with missing `name` field

### Development Experience
- [ ] Hot reload works: Change greeting in code, save, test again
- [ ] Environment variables are loaded: Check debug logs
- [ ] Request IDs appear in logs (if enabled)

## 🎯 Next Steps

After successful setup:

1. **Explore the Code**: 
   - Read through `src/index.ts` with the detailed comments
   - Understand the middleware pipeline
   - Examine the type definitions in `src/types.ts`

2. **Experiment**:
   - Modify the validation schema
   - Add new optional fields
   - Change the response format

3. **Test Error Scenarios**:
   - Send invalid data types
   - Test field length limits
   - Try unsupported language codes

4. **Learn Deployment**:
   - Follow [DEPLOYMENT.md](./DEPLOYMENT.md) when ready
   - Practice with staging environment first

5. **Explore Advanced Example**:
   - Progress to [fastify-production-api](../fastify-production-api/)
   - Learn authentication and CRUD patterns

## 🆘 Getting Help

If you encounter issues not covered here:

1. **Check the main README**: [../README.md](../README.md)
2. **Review the logs**: Look for detailed error messages in console output
3. **Verify environment**: Double-check Node.js and npm versions
4. **Clean installation**: Remove `node_modules` and `package-lock.json`, then `npm install`
5. **Create an issue**: Use the project's issue tracker with detailed error information

---

**Setup complete?** 🎉 Head back to the [main README](../README.md) to start exploring the API and learning the Noony framework patterns!