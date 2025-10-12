# Docker Deployment Guide

This guide explains how to build and run the SAML/OIDC Test Application using Docker.

## Prerequisites

- Docker installed (version 20.10 or later)
- Docker Compose installed (version 2.0 or later)

## Quick Start with Docker Compose

The easiest way to run the application:

```bash
# Build and start the container
npm run docker:up

# View logs
npm run docker:logs

# Stop the container
npm run docker:down
```

The application will be available at `http://localhost:3001`

## Manual Docker Commands

### Build the Image

```bash
# Using npm script
npm run docker:build

# Or directly with docker
docker build -t saml-oidc-test-app .
```

### Run the Container

```bash
# Using npm script
npm run docker:run

# Or directly with docker
docker run -d \
  --name saml-oidc-app \
  -p 3001:3001 \
  -v ./data:/app/data:ro \
  saml-oidc-test-app
```

### Using Docker Compose

```bash
# Start in detached mode
docker-compose up -d

# Start with logs
docker-compose up

# Stop the containers
docker-compose down

# View logs
docker-compose logs -f

# Rebuild and restart
docker-compose up -d --build
```

## Configuration

### Environment Variables

You can set environment variables in the `docker-compose.yml` file or pass them at runtime:

```yaml
environment:
  - NODE_ENV=production
  - PORT=3001
  - SESSION_SECRET=your-secret-key-here
```

Or with docker run:

```bash
docker run -d \
  -p 3001:3001 \
  -e SESSION_SECRET=your-secret-key \
  -v ./data:/app/data:ro \
  saml-oidc-test-app
```

### Configuration Files

The `data` directory is mounted as a volume so you can update configurations without rebuilding:

- `data/config.json` - Identity provider configurations
- `data/certificates/` - SAML certificates

To update the configuration:
1. Edit files in the `data` directory
2. Restart the container: `docker-compose restart`

## Docker Image Details

### Multi-Stage Build

The Dockerfile uses a multi-stage build for optimization:

1. **Stage 1 (frontend-build)**: Builds the React application
2. **Stage 2 (production)**: Creates the final runtime image with only production dependencies

### Image Size

The optimized image is approximately 200-250 MB (depending on dependencies).

### Health Check

The container includes a health check that verifies:
- The server is responding
- The `/api/config` endpoint returns a 200 status

Check container health:
```bash
docker ps
# Look for "healthy" in the STATUS column
```

## Troubleshooting

### View Container Logs

```bash
# All logs
docker logs saml-oidc-app

# Follow logs
docker logs -f saml-oidc-app

# Last 100 lines
docker logs --tail 100 saml-oidc-app
```

### Access Container Shell

```bash
docker exec -it saml-oidc-app sh
```

### Check if Container is Running

```bash
docker ps
```

### Port Already in Use

If port 3001 is already in use, modify the port mapping:

```bash
# Use port 8080 instead
docker run -p 8080:3001 saml-oidc-test-app
```

Or in `docker-compose.yml`:
```yaml
ports:
  - "8080:3001"
```

### Rebuild After Code Changes

```bash
# Stop and remove the old container
docker-compose down

# Rebuild and start
docker-compose up -d --build
```

## Production Deployment

### Best Practices

1. **Use a reverse proxy** (nginx, Traefik) for SSL/TLS termination
2. **Set a strong SESSION_SECRET** environment variable
3. **Use a persistent session store** instead of MemoryStore
4. **Mount config as read-only** (`:ro` flag)
5. **Use Docker secrets** for sensitive data
6. **Set resource limits** in docker-compose.yml:

```yaml
services:
  saml-oidc-app:
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Networking

To connect to other services (databases, external IdPs), use Docker networks:

```yaml
networks:
  saml-oidc-network:
    driver: bridge
  external-network:
    external: true
```

## Testing the Deployment

After starting the container, verify it's working:

```bash
# Test the API endpoint
curl http://localhost:3001/api/config

# Test the frontend
curl -I http://localhost:3001/

# Check health
docker inspect --format='{{.State.Health.Status}}' saml-oidc-app
```

## Cleanup

Remove all containers and images:

```bash
# Stop and remove containers
docker-compose down

# Remove the image
docker rmi saml-oidc-test-app

# Remove unused images and containers
docker system prune -a
```
