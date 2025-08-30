/*
================================================================================
Layer 1.1: System Configuration Management
================================================================================
Purpose: Core system configuration table and management procedures
Dependencies: 00_PreDeploymentChecks.sql
Execution Order: 2nd - Foundation for all configurable parameters

Features:
- SystemConfiguration table for runtime parameters
- GetConfigValue function for parameter retrieval
- SetConfigValue procedure for parameter updates
- Default configuration values for all system components
- Configuration validation and type safety

Author: Ecliptix Development Team
Version: 1.0.0
Created: 2024-08-24
================================================================================
*/

-- Use target database
USE [memberships]; -- Replace with your actual database name
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Layer 1.1: System Configuration Management';
PRINT 'Started at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
PRINT '================================================================================';

-- Log deployment start
DECLARE @DeploymentId UNIQUEIDENTIFIER = (
    SELECT TOP 1 DeploymentId 
    FROM dbo.DeploymentLog 
    WHERE Status = 'COMPLETED' 
    ORDER BY CreatedAt DESC
);

INSERT INTO dbo.DeploymentLog (DeploymentId, ScriptName, ExecutionOrder, Status)
VALUES (@DeploymentId, '01_SystemConfiguration.sql', 1, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- SYSTEM CONFIGURATION TABLE
    -- ============================================================================
    
    PRINT 'Creating SystemConfiguration table...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.SystemConfiguration', 'U') IS NOT NULL 
        DROP TABLE dbo.SystemConfiguration;
    
    CREATE TABLE dbo.SystemConfiguration (
        ConfigKey NVARCHAR(100) PRIMARY KEY,
        ConfigValue NVARCHAR(500) NOT NULL,
        DataType NVARCHAR(20) NOT NULL DEFAULT 'string',
        Description NVARCHAR(1000) NOT NULL,
        Category NVARCHAR(50) NOT NULL DEFAULT 'General',
        IsEncrypted BIT NOT NULL DEFAULT 0,
        CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
        UpdatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
        UpdatedBy NVARCHAR(100) DEFAULT SYSTEM_USER,
        CONSTRAINT CHK_SystemConfiguration_DataType 
            CHECK (DataType IN ('string', 'int', 'bool', 'decimal', 'datetime'))
    );
    
    -- Create indexes
    CREATE NONCLUSTERED INDEX IX_SystemConfiguration_Category 
        ON dbo.SystemConfiguration (Category);
    CREATE NONCLUSTERED INDEX IX_SystemConfiguration_DataType 
        ON dbo.SystemConfiguration (DataType);
    CREATE NONCLUSTERED INDEX IX_SystemConfiguration_UpdatedAt 
        ON dbo.SystemConfiguration (UpdatedAt);
    
    PRINT '✓ SystemConfiguration table created successfully';
    
    -- ============================================================================
    -- CONFIGURATION MANAGEMENT FUNCTIONS
    -- ============================================================================
    
    PRINT 'Creating configuration management functions...';
    
    -- Drop existing functions
    IF OBJECT_ID('dbo.GetConfigValue', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.GetConfigValue;
    
    -- Function to get configuration value with proper type conversion
    EXEC ('
    CREATE FUNCTION dbo.GetConfigValue(@ConfigKey NVARCHAR(100))
    RETURNS NVARCHAR(500)
    AS
    BEGIN
        DECLARE @ConfigValue NVARCHAR(500);
        
        SELECT @ConfigValue = ConfigValue
        FROM dbo.SystemConfiguration
        WHERE ConfigKey = @ConfigKey;
        
        RETURN ISNULL(@ConfigValue, '''');
    END;
    ');
    
    PRINT '✓ GetConfigValue function created successfully';
    
    -- ============================================================================
    -- CONFIGURATION MANAGEMENT PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating configuration management procedures...';
    
    -- Drop existing procedures
    IF OBJECT_ID('dbo.SetConfigValue', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.SetConfigValue;
    
    -- Procedure to set configuration value
    EXEC ('
    CREATE PROCEDURE dbo.SetConfigValue
        @ConfigKey NVARCHAR(100),
        @ConfigValue NVARCHAR(500),
        @UpdatedBy NVARCHAR(100) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Validate input
        IF @ConfigKey IS NULL OR LEN(TRIM(@ConfigKey)) = 0
        BEGIN
            RAISERROR(''Configuration key cannot be null or empty'', 16, 1);
            RETURN;
        END
        
        IF @ConfigValue IS NULL
        BEGIN
            RAISERROR(''Configuration value cannot be null'', 16, 1);
            RETURN;
        END
        
        -- Update configuration
        UPDATE dbo.SystemConfiguration
        SET ConfigValue = @ConfigValue,
            UpdatedAt = GETUTCDATE(),
            UpdatedBy = ISNULL(@UpdatedBy, SYSTEM_USER)
        WHERE ConfigKey = @ConfigKey;
        
        IF @@ROWCOUNT = 0
        BEGIN
            RAISERROR(''Configuration key %s not found'', 16, 1, @ConfigKey);
            RETURN;
        END
        
        SELECT 1 AS Success, ''Configuration updated successfully'' AS Message;
    END;
    ');
    
    PRINT '✓ SetConfigValue procedure created successfully';
    
    -- ============================================================================
    -- DEFAULT CONFIGURATION VALUES
    -- ============================================================================
    
    PRINT 'Inserting default configuration values...';
    
    -- Core Authentication Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('Authentication.MaxFailedAttempts', '5', 'int', 'Maximum failed authentication attempts before lockout', 'Security'),
    ('Authentication.LockoutDurationMinutes', '5', 'int', 'Duration of account lockout in minutes', 'Security'),
    ('Authentication.ContextExpirationHours', '24', 'int', 'Default authentication context expiration in hours', 'Security'),
    ('Authentication.MaxSessionsPerUser', '5', 'int', 'Maximum concurrent sessions per user', 'Security'),
    ('Authentication.MaxLockoutDuration', '1440', 'int', 'Maximum lockout duration in minutes (24 hours)', 'Security');
    
    -- OTP Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('OTP.MaxAttempts', '5', 'int', 'Maximum OTP attempts per flow', 'Security'),
    ('OTP.ExpirationMinutes', '10', 'int', 'OTP expiration time in minutes', 'Security'),
    ('OTP.ResendCooldownSeconds', '30', 'int', 'Minimum seconds between OTP resend requests', 'Security'),
    ('OTP.EnableRateLimitTracking', '1', 'bool', 'Enable OTP rate limit tracking and enforcement', 'Security');
    
    -- Rate Limiting Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('RateLimit.MaxFlowsPerHour', '5', 'int', 'Maximum verification flows per phone number per hour', 'Security'),
    ('RateLimit.WindowHours', '1', 'int', 'Rate limiting window in hours', 'Security');
    
    -- Database Performance Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('Database.CleanupBatchSize', '1000', 'int', 'Batch size for cleanup operations', 'Performance'),
    ('Database.RetentionDays', '90', 'int', 'Data retention period in days', 'Performance');
    
    -- Monitoring Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('Monitoring.EnableMetrics', '1', 'bool', 'Enable performance metrics collection', 'Monitoring'),
    ('Monitoring.MetricsBatchSize', '100', 'int', 'Batch size for metrics processing', 'Monitoring');
    
    -- Audit Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('Audit.RetentionDays', '365', 'int', 'Audit log retention period in days', 'Compliance'),
    ('Audit.LogValidations', '0', 'bool', 'Enable detailed validation logging (high frequency)', 'Compliance'),
    ('Audit.LogOtpChanges', '1', 'bool', 'Enable detailed OTP change logging in triggers', 'Compliance'),
    ('Audit.LogMembershipChanges', '1', 'bool', 'Enable detailed membership change logging', 'Compliance');
    
    -- Membership Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('Membership.SuspiciousActivityThreshold', '3', 'int', 'Unique IPs threshold for suspicious activity', 'Security'),
    ('Membership.EnableGeoBlocking', '0', 'bool', 'Enable geographic-based access blocking', 'Security');
    
    -- Verification Flow Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('VerificationFlow.DefaultExpirationMinutes', '5', 'int', 'Default verification flow expiration in minutes', 'Security');
    
    -- Circuit Breaker Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('CircuitBreaker.FailureThreshold', '5', 'int', 'Number of failures before circuit opens', 'Resilience'),
    ('CircuitBreaker.SuccessThreshold', '3', 'int', 'Number of successes to close circuit', 'Resilience'),
    ('CircuitBreaker.TimeoutMinutes', '1', 'int', 'Circuit breaker timeout in minutes', 'Resilience');
    
    -- System Maintenance Settings
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
    ('Maintenance.AutoCleanupEnabled', '1', 'bool', 'Enable automatic cleanup procedures', 'Maintenance'),
    ('Maintenance.CleanupScheduleHours', '2', 'int', 'Hour of day to run cleanup (24-hour format)', 'Maintenance');
    
    DECLARE @ConfigCount INT;
    SELECT @ConfigCount = COUNT(*) FROM dbo.SystemConfiguration;
    PRINT '✓ Inserted ' + CAST(@ConfigCount AS NVARCHAR(10)) + ' default configuration values';
    
    -- ============================================================================
    -- CONFIGURATION VALIDATION
    -- ============================================================================
    
    PRINT 'Validating configuration setup...';
    
    -- Test configuration retrieval
    DECLARE @TestValue NVARCHAR(500) = dbo.GetConfigValue('Authentication.MaxFailedAttempts');
    IF @TestValue != '5'
    BEGIN
        RAISERROR('Configuration retrieval test failed. Expected: 5, Got: %s', 16, 1, @TestValue);
    END
    
    -- Test configuration update
    DECLARE @TestResult TABLE (Success BIT, Message NVARCHAR(255));
    INSERT INTO @TestResult
    EXEC dbo.SetConfigValue 'Authentication.MaxFailedAttempts', '5', 'SYSTEM_VALIDATION';
    
    IF NOT EXISTS (SELECT 1 FROM @TestResult WHERE Success = 1)
    BEGIN
        RAISERROR('Configuration update test failed', 16, 1);
    END
    
    PRINT '✓ Configuration validation completed successfully';
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = @ConfigCount
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 1.1: System Configuration Management Completed Successfully';
    PRINT 'Configuration entries: ' + CAST(@ConfigCount AS NVARCHAR(10));
    PRINT 'Next: Layer 1.2 - Logging Infrastructure';
    PRINT 'Finished at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
    PRINT '================================================================================';

END TRY
BEGIN CATCH
    -- Rollback on error
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    
    -- Log the error
    UPDATE dbo.DeploymentLog 
    SET Status = 'FAILED', 
        EndTime = GETUTCDATE(), 
        ErrorMessage = ERROR_MESSAGE()
    WHERE Id = @LogId;
    
    -- Re-throw the error
    PRINT 'ERROR in Layer 1.1: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO