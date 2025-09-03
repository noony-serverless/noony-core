# Hello World Simple - Deployment Guide

This guide covers deploying the Hello World Simple example to Google Cloud Functions, including setup, configuration, monitoring, and troubleshooting.

## 🎯 Deployment Overview

This example supports multiple deployment strategies:

- **Google Cloud Functions**: Serverless, auto-scaling deployment
- **Google Cloud Run**: Containerized deployment with more control
- **Local Docker**: Containerized local testing
- **Development**: Local Functions Framework for testing

## 🚀 Google Cloud Functions Deployment

### Prerequisites

1. **Google Cloud Project**: Active project with billing enabled
2. **Google Cloud SDK**: Installed and authenticated
3. **Required APIs**: Enabled for your project
4. **IAM Permissions**: Sufficient permissions for function deployment

### 1. Initial Setup

#### Install Google Cloud SDK

```bash
# macOS (using Homebrew)
brew install google-cloud-sdk

# Ubuntu/Debian
sudo apt-get install google-cloud-sdk

# Or download installer from: https://cloud.google.com/sdk/docs/install
```

#### Authenticate and Configure

```bash
# Authenticate with Google Cloud
gcloud auth login

# Set your project
gcloud config set project YOUR_PROJECT_ID

# Verify configuration
gcloud config list
```

#### Enable Required APIs

```bash
# Enable Cloud Functions API
gcloud services enable cloudfunctions.googleapis.com

# Enable Cloud Build API (required for function deployment)
gcloud services enable cloudbuild.googleapis.com

# Enable Cloud Logging API (for monitoring)
gcloud services enable logging.googleapis.com

# Verify enabled services
gcloud services list --enabled --filter="cloudfunctions OR cloudbuild OR logging"
```

### 2. Prepare for Deployment

#### Build and Test Locally First

```bash
# Ensure TypeScript builds without errors
npm run build

# Test locally
npm run dev
# Test with curl in another terminal

# Run linting
npm run lint
```

#### Review Deployment Configuration

Check your `package.json` for deployment settings:

```json
{
  "scripts": {
    "deploy": "gcloud functions deploy helloWorld --runtime nodejs18 --trigger-http --allow-unauthenticated --source=."
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
```

### 3. Deploy to Google Cloud Functions

#### Basic Deployment

```bash
# Deploy using npm script (recommended)
npm run deploy
```

#### Advanced Deployment with Custom Settings

```bash
# Deploy with specific configuration
gcloud functions deploy helloWorld \
  --runtime nodejs18 \
  --trigger-http \
  --allow-unauthenticated \
  --memory 256MB \
  --timeout 60s \
  --max-instances 100 \
  --source . \
  --entry-point helloWorld
```

#### Deployment Options Explained

| Option | Description | Recommended Value |
|--------|-------------|-------------------|
| `--runtime` | Node.js runtime version | `nodejs18` |
| `--trigger-http` | Enable HTTP trigger | Required for API |
| `--allow-unauthenticated` | Public access | Use for public APIs |
| `--memory` | Memory allocation | `256MB` (sufficient) |
| `--timeout` | Maximum execution time | `60s` (default) |
| `--max-instances` | Scaling limit | `100` (adjust as needed) |
| `--source` | Source directory | `.` (current directory) |
| `--entry-point` | Function name | `helloWorld` |

#### Environment Variables

```bash
# Deploy with environment variables
gcloud functions deploy helloWorld \
  --runtime nodejs18 \
  --trigger-http \
  --allow-unauthenticated \
  --set-env-vars="NODE_ENV=production,LOG_LEVEL=info,DEFAULT_GREETING=Welcome"
```

### 4. Verify Deployment

#### Check Deployment Status

```bash
# List deployed functions
gcloud functions list

# Get specific function details
gcloud functions describe helloWorld

# View function URL
gcloud functions describe helloWorld --format="value(httpsTrigger.url)"
```

#### Test Deployed Function

```bash
# Get the function URL
FUNCTION_URL=$(gcloud functions describe helloWorld --format="value(httpsTrigger.url)")
echo "Function URL: $FUNCTION_URL"

# Test the deployed function
curl -X POST $FUNCTION_URL \
  -H "Content-Type: application/json" \
  -d '{"name": "Production User"}'
```

## 📊 Monitoring and Logging

### View Logs

```bash
# View real-time logs
gcloud functions logs tail helloWorld

# View logs from last hour
gcloud functions logs read helloWorld --limit 50

# View logs with specific severity
gcloud functions logs read helloWorld --severity ERROR
```

### Cloud Console Monitoring

1. **Open Cloud Console**: https://console.cloud.google.com
2. **Navigate to Cloud Functions**: Compute > Cloud Functions
3. **Click your function**: `helloWorld`
4. **View metrics**: Invocations, errors, duration, memory usage

### Set Up Alerts

```bash
# Create alert policy for errors
gcloud alpha monitoring policies create \
  --policy-from-file=alert-policy.yaml
```

Example `alert-policy.yaml`:
```yaml
displayName: "Hello World Function Errors"
conditions:
  - displayName: "Error rate too high"
    conditionThreshold:
      filter: 'resource.type="cloud_function" resource.label.function_name="helloWorld"'
      comparison: COMPARISON_GREATER_THAN
      thresholdValue: 0.1
      duration: 300s
notificationChannels:
  - "projects/YOUR_PROJECT/notificationChannels/YOUR_CHANNEL_ID"
```

## 🔧 Configuration Management

### Environment-Specific Deployments

#### Staging Deployment

```bash
# Deploy to staging with staging configuration
gcloud functions deploy helloWorld-staging \
  --runtime nodejs18 \
  --trigger-http \
  --allow-unauthenticated \
  --set-env-vars="NODE_ENV=staging,DEBUG=true,LOG_LEVEL=debug"
```

#### Production Deployment

```bash
# Deploy to production with production configuration
gcloud functions deploy helloWorld \
  --runtime nodejs18 \
  --trigger-http \
  --allow-unauthenticated \
  --set-env-vars="NODE_ENV=production,LOG_LEVEL=warn" \
  --memory 512MB \
  --timeout 30s
```

### Configuration File Approach

Create `deployment-configs/`:

**staging.yaml:**
```yaml
name: helloWorld-staging
runtime: nodejs18
httpsTrigger: {}
environmentVariables:
  NODE_ENV: staging
  DEBUG: "true"
  LOG_LEVEL: debug
availableMemoryMb: 256
timeout: 60s
```

**production.yaml:**
```yaml
name: helloWorld
runtime: nodejs18
httpsTrigger: {}
environmentVariables:
  NODE_ENV: production
  LOG_LEVEL: warn
availableMemoryMb: 512
timeout: 30s
maxInstances: 100
```

Deploy using config files:
```bash
# Deploy staging
gcloud functions deploy --config staging.yaml

# Deploy production  
gcloud functions deploy --config production.yaml
```

## 🔒 Security Considerations

### Authentication Setup

#### Require Authentication

```bash
# Deploy with authentication required
gcloud functions deploy helloWorld \
  --runtime nodejs18 \
  --trigger-http \
  --no-allow-unauthenticated
```

#### Service Account Setup

```bash
# Create service account for the function
gcloud iam service-accounts create hello-world-function \
  --display-name="Hello World Function Service Account"

# Deploy with custom service account
gcloud functions deploy helloWorld \
  --runtime nodejs18 \
  --trigger-http \
  --service-account=hello-world-function@YOUR_PROJECT.iam.gserviceaccount.com
```

### Network Security

```bash
# Deploy with VPC connector (for private resources)
gcloud functions deploy helloWorld \
  --runtime nodejs18 \
  --trigger-http \
  --vpc-connector YOUR_VPC_CONNECTOR \
  --egress-settings private-ranges-only
```

## 🚀 Alternative Deployment Methods

### Google Cloud Run

```bash
# Build container image
gcloud builds submit --tag gcr.io/YOUR_PROJECT/hello-world

# Deploy to Cloud Run
gcloud run deploy hello-world \
  --image gcr.io/YOUR_PROJECT/hello-world \
  --platform managed \
  --allow-unauthenticated \
  --port 8080
```

### Docker Deployment

Create `Dockerfile`:
```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY dist ./dist
COPY src ./src

EXPOSE 8080
CMD ["npm", "start"]
```

Build and run:
```bash
# Build image
docker build -t hello-world-noony .

# Run locally
docker run -p 8080:8080 \
  -e NODE_ENV=production \
  hello-world-noony
```

## 🛠 Troubleshooting Deployment Issues

### Common Deployment Errors

#### Error: "Build failed"

```bash
# Check build logs
gcloud functions logs read helloWorld --limit 10

# Common causes:
# 1. TypeScript compilation errors
npm run build

# 2. Missing dependencies
npm install

# 3. Node.js version mismatch
# Update package.json engines field
```

#### Error: "Function failed to start"

```bash
# Check startup logs
gcloud functions logs tail helloWorld

# Common causes:
# 1. Wrong entry point
gcloud functions deploy helloWorld --entry-point=helloWorld

# 2. Missing exports
grep -n "export.*helloWorld" src/index.ts

# 3. Runtime errors
npm run dev  # Test locally first
```

#### Error: "Timeout during deployment"

```bash
# Increase deployment timeout
gcloud config set functions/region us-central1

# Clean up failed deployments
gcloud functions delete helloWorld-temp
```

### Performance Issues

#### High Memory Usage

```bash
# Check memory metrics in Cloud Console
# Increase memory allocation
gcloud functions deploy helloWorld --memory 512MB
```

#### Cold Start Latency

```bash
# Reduce cold starts with min instances
gcloud functions deploy helloWorld --min-instances 1

# Optimize bundle size
npm run build
ls -la dist/  # Check file sizes
```

### Debugging Production Issues

```bash
# Enable debug logging temporarily
gcloud functions deploy helloWorld \
  --update-env-vars="DEBUG=true,LOG_LEVEL=debug"

# Check error rates
gcloud logging read 'resource.type="cloud_function" AND resource.labels.function_name="helloWorld" AND severity="ERROR"' \
  --limit 10 \
  --format json

# Revert debug settings
gcloud functions deploy helloWorld \
  --update-env-vars="DEBUG=false,LOG_LEVEL=info"
```

## 📈 Performance Optimization

### Memory and CPU Optimization

```bash
# Test different memory allocations
gcloud functions deploy helloWorld --memory 128MB  # Minimum
gcloud functions deploy helloWorld --memory 256MB  # Recommended
gcloud functions deploy helloWorld --memory 512MB  # High load
```

### Scaling Configuration

```bash
# Configure scaling
gcloud functions deploy helloWorld \
  --min-instances 0 \      # Cost optimization
  --max-instances 100 \    # Traffic spike protection
  --concurrency 1000       # Requests per instance
```

## 📋 Deployment Checklist

Before deploying to production:

- [ ] **Code Quality**
  - [ ] All TypeScript compiles without errors
  - [ ] ESLint passes without warnings
  - [ ] Local testing completed successfully

- [ ] **Configuration**
  - [ ] Environment variables configured for production
  - [ ] Memory and timeout settings optimized
  - [ ] Authentication properly configured

- [ ] **Security**
  - [ ] No sensitive data in environment variables
  - [ ] Appropriate IAM permissions set
  - [ ] Network security configured if needed

- [ ] **Monitoring**
  - [ ] Logging level appropriate for environment
  - [ ] Alerts configured for errors and performance
  - [ ] Monitoring dashboard set up

- [ ] **Testing**
  - [ ] Function deployed to staging first
  - [ ] Load testing completed
  - [ ] Error scenarios tested

---

**Ready to deploy?** 🚀 Start with the staging deployment, verify everything works, then promote to production following the checklist above!