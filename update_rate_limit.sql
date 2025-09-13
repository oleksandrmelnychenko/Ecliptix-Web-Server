-- Update rate limit configuration for development
-- This increases the verification flow rate limit from 5 to 100 per hour per phone number

USE [memberships]; -- Replace with your actual database name if different
GO

-- Update the rate limit configuration
UPDATE dbo.SystemConfiguration 
SET ConfigValue = '100',
    UpdatedAt = GETUTCDATE()
WHERE ConfigKey = 'RateLimit.MaxFlowsPerHour';

-- Verify the update
SELECT 
    ConfigKey,
    ConfigValue,
    DataType,
    Description,
    Category,
    UpdatedAt
FROM dbo.SystemConfiguration 
WHERE ConfigKey = 'RateLimit.MaxFlowsPerHour';

PRINT 'Rate limit updated successfully from 5 to 100 flows per hour per phone number';