# Multi-stage build for optimized image size

# Stage 1: Build the React frontend
FROM node:24-alpine AS frontend-build

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm install

# Copy source code
COPY src ./src
COPY public ./public

# Build the React app
RUN npm run build

# Stage 2: Setup the production server
FROM node:24-alpine AS production

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm install --omit=dev

# Copy server code
COPY server ./server

# Copy built frontend from previous stage
COPY --from=frontend-build /app/build ./build

# Copy data directory (config and certificates)
RUN mkdir data
#COPY data ./data

# Expose the port
EXPOSE 3001

# Set environment to production
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/api/config', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start the server
CMD ["node", "server/index.js"]
