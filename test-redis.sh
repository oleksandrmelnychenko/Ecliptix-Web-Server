#!/bin/bash
echo "🧪 Testing Redis connection..."

# Test Redis connection
echo "1. Testing Redis ping..."
docker exec ecliptix-redis redis-cli ping

# Set a test key
echo "2. Setting test key..."
docker exec ecliptix-redis redis-cli SET test:key "Hello Redis from Ecliptix"

# Get the test key
echo "3. Getting test key..."
docker exec ecliptix-redis redis-cli GET test:key

# Check memory usage
echo "4. Memory info..."
docker exec ecliptix-redis redis-cli INFO memory | grep used_memory_human

# List all keys
echo "5. Current keys..."
docker exec ecliptix-redis redis-cli KEYS "*"

echo "✅ Redis test complete!"