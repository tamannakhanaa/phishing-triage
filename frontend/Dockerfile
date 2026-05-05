# Frontend Dockerfile
# Using multi-stage build for a smaller production image

# --- Builder Stage ---
# Installs dependencies and builds the React app
FROM node:20-alpine as builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Copy the rest of the app's source code
COPY . .

# Build the app
RUN npm run build

# --- Final Stage ---
# Uses a lightweight server to serve the static files
FROM nginx:1.25-alpine

# Copy the built app from the builder stage
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

