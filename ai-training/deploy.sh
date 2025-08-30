#!/bin/bash
# Quick deployment script for Have I Been Rekt AI Training System

echo "🚀 Deploying Have I Been Rekt AI Training System"
echo "================================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first:"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose:"
    echo "   https://docs.docker.com/compose/install/"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  IMPORTANT: Edit .env file with your API keys before proceeding!"
    echo "   Required keys: HIBP_API_KEY, VIRUSTOTAL_API_KEY"
    echo "   Optional keys: CHAINALYSIS_API_KEY"
    echo ""
    read -p "Have you added your API keys to .env? (y/N): " confirm
    if [[ $confirm != [yY] ]]; then
        echo "Please edit .env file first, then run this script again."
        exit 1
    fi
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p cache models logs data

# Build and start services
echo "🏗️  Building Docker images..."
docker-compose build

echo "🚀 Starting services..."
docker-compose up -d ai-api redis

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check health
echo "🏥 Checking service health..."
curl -f http://localhost:8000/health || {
    echo "❌ Health check failed. Checking logs..."
    docker-compose logs ai-api
    exit 1
}

echo ""
echo "✅ Deployment successful!"
echo "================================================"
echo "🌐 API Server: http://localhost:8000"
echo "📚 API Docs: http://localhost:8000/docs"
echo "🏥 Health Check: http://localhost:8000/health"
echo "📊 Example Request:"
echo '   curl -X POST http://localhost:8000/api/v1/analyze \'
echo '     -H "Content-Type: application/json" \'
echo '     -d {"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}'
echo ""
echo "🔧 To stop: docker-compose down"
echo "📋 To view logs: docker-compose logs -f ai-api"