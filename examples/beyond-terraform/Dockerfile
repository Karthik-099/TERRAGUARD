# Intentionally weak Dockerfile.
FROM node:latest
ADD https://example.com/install.sh /tmp/install.sh
RUN curl -fsSL https://example.com/setup.sh | sh
ENV API_TOKEN=abc123secretvalue
COPY . /app
CMD ["node", "/app/server.js"]
