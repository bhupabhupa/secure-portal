# Secure Portal SPA — build with Vite, serve as static files via nginx
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
# Build-time config: where Keycloak lives publicly, and the API base
# ("" = same-origin /api/* via the reverse proxy in production).
ARG VITE_AUTH_URL=""
ARG VITE_API_URL=""
ENV VITE_AUTH_URL=$VITE_AUTH_URL VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
