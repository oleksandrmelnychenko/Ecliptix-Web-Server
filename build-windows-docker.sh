#!/bin/bash

echo "Building Ecliptix for Windows Docker deployment..."

# Build the Windows Docker image
echo "Building Docker image for Windows..."
docker build -f Ecliptix.Core/Dockerfile -t ecliptix-windows:latest .

if [ $? -eq 0 ]; then
    echo "✅ Docker image built successfully!"
    echo "To run the container:"
    echo "docker run -p 8080:8080 ecliptix-windows:latest"
else
    echo "❌ Docker build failed!"
    exit 1
fi