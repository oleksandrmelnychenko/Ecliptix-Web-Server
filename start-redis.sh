#!/bin/bash
# Start Redis with Docker Compose
echo "Starting Redis with Docker Compose..."
docker-compose up -d redis

# Wait for Redis to be ready
echo "Waiting for Redis to be ready..."
until docker exec ecliptix-redis redis-cli ping | grep -q PONG; do
    echo "Waiting for Redis..."
    sleep 1
done

echo "✅ Redis is ready!"
echo "📊 Redis Commander UI available at: http://localhost:8081"
echo "🔗 Redis connection: localhost:6379"

# Start Redis Commander
echo "Starting Redis Commander..."
docker-compose up -d redis-commander

echo "🚀 Redis setup complete!"