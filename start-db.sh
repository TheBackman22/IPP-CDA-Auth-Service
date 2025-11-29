#!/bin/bash

# IPP-CDA Auth Service - PostgreSQL Docker Startup Script
# This script starts PostgreSQL, waits for it to be ready, and runs migrations

set -e

echo "=========================================="
echo "IPP-CDA Auth Service - Database Setup"
echo "=========================================="
echo ""

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "Error: docker-compose is not installed"
    exit 1
fi

# Start PostgreSQL container
echo "1. Starting PostgreSQL container..."
docker-compose up -d
echo "   ✓ PostgreSQL container started"
echo ""

# Wait for PostgreSQL to be ready
echo "2. Waiting for PostgreSQL to be ready..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if docker-compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1; then
        echo "   ✓ PostgreSQL is ready"
        break
    fi
    attempt=$((attempt + 1))
    echo "   Waiting... ($attempt/$max_attempts)"
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "   ✗ PostgreSQL failed to start"
    exit 1
fi

echo ""

# Run migration script
echo "3. Running database migration (V1__initial_schema.sql)..."
docker-compose exec -T postgres psql -U postgres -d ippcda -f /docker-entrypoint-initdb.d/V1__initial_schema.sql > /dev/null 2>&1
echo "   ✓ Migration completed"
echo ""

# Verify tables were created
echo "4. Verifying database schema..."
echo "   Tables created:"
docker-compose exec -T postgres psql -U postgres -d ippcda -c "\dt auth_schema.*" 2>/dev/null | grep -E "users|refresh_tokens" | awk '{print "   - " $2}'
echo ""

echo "=========================================="
echo "✓ Database setup complete!"
echo "=========================================="
echo ""
echo "Connection details:"
echo "  Host:     localhost"
echo "  Port:     5432"
echo "  Database: ippcda"
echo "  User:     postgres"
echo "  Password: postgres"
echo ""
echo "To stop the database, run: docker-compose down"
echo "To view logs, run:         docker-compose logs -f postgres"
