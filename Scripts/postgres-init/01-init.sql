-- PostgreSQL Initialization Script for Ecliptix
-- This script runs automatically when the container is first created

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Set timezone to UTC
SET timezone = 'UTC';

-- Log initialization
DO $$ 
BEGIN 
    RAISE NOTICE 'Ecliptix database initialized successfully';
END $$;
