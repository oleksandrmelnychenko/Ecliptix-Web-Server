-- Production Infrastructure for Ecliptix Database
-- This script creates supporting tables and procedures for production-ready operation
-- Version: 1.0.0
-- Author: Ecliptix Development Team
-- Created: 2024-08-24

BEGIN TRANSACTION;
GO

-- ============================================================================
-- SYSTEM CONFIGURATION MANAGEMENT
-- ============================================================================

-- Drop existing objects if they exist
IF OBJECT_ID('dbo.GetConfigValue', 'FN') IS NOT NULL DROP FUNCTION dbo.GetConfigValue;
IF OBJECT_ID('dbo.SetConfigValue', 'P') IS NOT NULL DROP PROCEDURE dbo.SetConfigValue;
IF OBJECT_ID('dbo.SystemConfiguration', 'U') IS NOT NULL DROP TABLE dbo.SystemConfiguration;
GO

-- System Configuration Table
CREATE TABLE dbo.SystemConfiguration (
    ConfigKey NVARCHAR(100) PRIMARY KEY,
    ConfigValue NVARCHAR(500) NOT NULL,
    DataType NVARCHAR(20) NOT NULL DEFAULT 'string',
    Description NVARCHAR(1000) NOT NULL,
    Category NVARCHAR(50) NOT NULL DEFAULT 'General',
    IsEncrypted BIT NOT NULL DEFAULT 0,
    CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
    UpdatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
    UpdatedBy NVARCHAR(100) DEFAULT SYSTEM_USER
);

-- Insert default configuration values
INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) VALUES
('Authentication.MaxFailedAttempts', '5', 'int', 'Maximum failed authentication attempts before lockout', 'Security'),
('Authentication.LockoutDurationMinutes', '5', 'int', 'Duration of account lockout in minutes', 'Security'),
('Authentication.ContextExpirationHours', '24', 'int', 'Default authentication context expiration in hours', 'Security'),
('OTP.MaxAttempts', '5', 'int', 'Maximum OTP attempts per flow', 'Security'),
('OTP.ExpirationMinutes', '10', 'int', 'OTP expiration time in minutes', 'Security'),
('OTP.ResendCooldownSeconds', '30', 'int', 'Minimum seconds between OTP resend requests', 'Security'),
('Database.CleanupBatchSize', '1000', 'int', 'Batch size for cleanup operations', 'Performance'),
('Database.RetentionDays', '90', 'int', 'Data retention period in days', 'Performance'),
('RateLimit.MaxFlowsPerHour', '5', 'int', 'Maximum verification flows per phone number per hour', 'Security'),
('RateLimit.WindowHours', '1', 'int', 'Rate limiting window in hours', 'Security'),
('Monitoring.EnableMetrics', '1', 'bool', 'Enable performance metrics collection', 'Monitoring'),
('Audit.RetentionDays', '365', 'int', 'Audit log retention period in days', 'Compliance');
GO

-- Function to get configuration value with proper type conversion
CREATE FUNCTION dbo.GetConfigValue(@ConfigKey NVARCHAR(100))
RETURNS NVARCHAR(500)
AS
BEGIN
    DECLARE @ConfigValue NVARCHAR(500);
    
    SELECT @ConfigValue = ConfigValue
    FROM dbo.SystemConfiguration
    WHERE ConfigKey = @ConfigKey;
    
    RETURN ISNULL(@ConfigValue, '');
END;
GO

-- Procedure to set configuration value
CREATE PROCEDURE dbo.SetConfigValue
    @ConfigKey NVARCHAR(100),
    @ConfigValue NVARCHAR(500),
    @UpdatedBy NVARCHAR(100) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    UPDATE dbo.SystemConfiguration
    SET ConfigValue = @ConfigValue,
        UpdatedAt = GETUTCDATE(),
        UpdatedBy = ISNULL(@UpdatedBy, SYSTEM_USER)
    WHERE ConfigKey = @ConfigKey;
    
    IF @@ROWCOUNT = 0
    BEGIN
        RAISERROR('Configuration key %s not found', 16, 1, @ConfigKey);
        RETURN;
    END
    
    SELECT 1 AS Success, 'Configuration updated successfully' AS Message;
END;
GO

-- ============================================================================
-- COMPREHENSIVE AUDIT AND LOGGING INFRASTRUCTURE
-- ============================================================================

-- Drop existing audit/logging objects
IF OBJECT_ID('dbo.LogError', 'P') IS NOT NULL DROP PROCEDURE dbo.LogError;
IF OBJECT_ID('dbo.LogAuditEvent', 'P') IS NOT NULL DROP PROCEDURE dbo.LogAuditEvent;
IF OBJECT_ID('dbo.LogPerformanceMetric', 'P') IS NOT NULL DROP PROCEDURE dbo.LogPerformanceMetric;
IF OBJECT_ID('dbo.CleanupAuditLogs', 'P') IS NOT NULL DROP PROCEDURE dbo.CleanupAuditLogs;
IF OBJECT_ID('dbo.PerformanceMetrics', 'U') IS NOT NULL DROP TABLE dbo.PerformanceMetrics;
IF OBJECT_ID('dbo.AuditLog', 'U') IS NOT NULL DROP TABLE dbo.AuditLog;
IF OBJECT_ID('dbo.ErrorLog', 'U') IS NOT NULL DROP TABLE dbo.ErrorLog;
GO

-- Enhanced Error Logging Table
CREATE TABLE dbo.ErrorLog (
    Id BIGINT IDENTITY(1,1) PRIMARY KEY,
    ProcedureName NVARCHAR(100) NOT NULL,
    ErrorNumber INT NOT NULL,
    ErrorMessage NVARCHAR(MAX) NOT NULL,
    ErrorSeverity INT NOT NULL,
    ErrorState INT NOT NULL,
    ErrorLine INT,
    Parameters NVARCHAR(MAX),
    StackTrace NVARCHAR(MAX),
    UserId UNIQUEIDENTIFIER,
    SessionId NVARCHAR(100),
    IpAddress NVARCHAR(45),
    UserAgent NVARCHAR(500),
    CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE()
);
CREATE NONCLUSTERED INDEX IX_ErrorLog_CreatedAt ON dbo.ErrorLog (CreatedAt);
CREATE NONCLUSTERED INDEX IX_ErrorLog_ProcedureName_CreatedAt ON dbo.ErrorLog (ProcedureName, CreatedAt);
GO

-- Comprehensive Audit Log Table
CREATE TABLE dbo.AuditLog (
    Id BIGINT IDENTITY(1,1) PRIMARY KEY,
    TableName NVARCHAR(100) NOT NULL,
    OperationType NVARCHAR(20) NOT NULL, -- INSERT, UPDATE, DELETE, SELECT
    RecordId NVARCHAR(50) NOT NULL,
    OldValues NVARCHAR(MAX),
    NewValues NVARCHAR(MAX),
    FieldsChanged NVARCHAR(500),
    UserId UNIQUEIDENTIFIER,
    SessionId NVARCHAR(100),
    IpAddress NVARCHAR(45),
    UserAgent NVARCHAR(500),
    ApplicationContext NVARCHAR(200),
    Success BIT NOT NULL DEFAULT 1,
    ErrorMessage NVARCHAR(500),
    CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE()
);
CREATE NONCLUSTERED INDEX IX_AuditLog_CreatedAt ON dbo.AuditLog (CreatedAt);
CREATE NONCLUSTERED INDEX IX_AuditLog_TableName_CreatedAt ON dbo.AuditLog (TableName, CreatedAt);
CREATE NONCLUSTERED INDEX IX_AuditLog_RecordId ON dbo.AuditLog (RecordId);
CREATE NONCLUSTERED INDEX IX_AuditLog_UserId_CreatedAt ON dbo.AuditLog (UserId, CreatedAt);
GO

-- Performance Metrics Table
CREATE TABLE dbo.PerformanceMetrics (
    Id BIGINT IDENTITY(1,1) PRIMARY KEY,
    ProcedureName NVARCHAR(100) NOT NULL,
    OperationType NVARCHAR(50) NOT NULL,
    ExecutionTimeMs INT NOT NULL,
    RowsAffected INT NOT NULL DEFAULT 0,
    CpuTimeMs INT,
    LogicalReads BIGINT,
    PhysicalReads BIGINT,
    Parameters NVARCHAR(MAX),
    Success BIT NOT NULL DEFAULT 1,
    ErrorMessage NVARCHAR(500),
    CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE()
);
CREATE NONCLUSTERED INDEX IX_PerformanceMetrics_CreatedAt ON dbo.PerformanceMetrics (CreatedAt);
CREATE NONCLUSTERED INDEX IX_PerformanceMetrics_ProcedureName_CreatedAt ON dbo.PerformanceMetrics (ProcedureName, CreatedAt);
GO

-- Error Logging Procedure
CREATE PROCEDURE dbo.LogError
    @ProcedureName NVARCHAR(100),
    @ErrorNumber INT = NULL,
    @ErrorMessage NVARCHAR(MAX),
    @ErrorSeverity INT = NULL,
    @ErrorState INT = NULL,
    @ErrorLine INT = NULL,
    @Parameters NVARCHAR(MAX) = NULL,
    @UserId UNIQUEIDENTIFIER = NULL,
    @SessionId NVARCHAR(100) = NULL,
    @IpAddress NVARCHAR(45) = NULL,
    @UserAgent NVARCHAR(500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        INSERT INTO dbo.ErrorLog (
            ProcedureName, ErrorNumber, ErrorMessage, ErrorSeverity, ErrorState,
            ErrorLine, Parameters, UserId, SessionId, IpAddress, UserAgent
        )
        VALUES (
            @ProcedureName, ISNULL(@ErrorNumber, ERROR_NUMBER()), @ErrorMessage,
            ISNULL(@ErrorSeverity, ERROR_SEVERITY()), ISNULL(@ErrorState, ERROR_STATE()),
            ISNULL(@ErrorLine, ERROR_LINE()), @Parameters, @UserId, @SessionId, @IpAddress, @UserAgent
        );
    END TRY
    BEGIN CATCH
        -- If logging fails, we don't want to break the main operation
        -- Could implement a fallback logging mechanism here
    END CATCH
END;
GO

-- Audit Event Logging Procedure
CREATE PROCEDURE dbo.LogAuditEvent
    @TableName NVARCHAR(100),
    @OperationType NVARCHAR(20),
    @RecordId NVARCHAR(50),
    @OldValues NVARCHAR(MAX) = NULL,
    @NewValues NVARCHAR(MAX) = NULL,
    @FieldsChanged NVARCHAR(500) = NULL,
    @UserId UNIQUEIDENTIFIER = NULL,
    @SessionId NVARCHAR(100) = NULL,
    @IpAddress NVARCHAR(45) = NULL,
    @UserAgent NVARCHAR(500) = NULL,
    @ApplicationContext NVARCHAR(200) = NULL,
    @Success BIT = 1,
    @ErrorMessage NVARCHAR(500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        INSERT INTO dbo.AuditLog (
            TableName, OperationType, RecordId, OldValues, NewValues, FieldsChanged,
            UserId, SessionId, IpAddress, UserAgent, ApplicationContext, Success, ErrorMessage
        )
        VALUES (
            @TableName, @OperationType, @RecordId, @OldValues, @NewValues, @FieldsChanged,
            @UserId, @SessionId, @IpAddress, @UserAgent, @ApplicationContext, @Success, @ErrorMessage
        );
    END TRY
    BEGIN CATCH
        -- Silently handle audit logging failures to avoid breaking main operations
    END CATCH
END;
GO

-- Performance Metrics Logging Procedure
CREATE PROCEDURE dbo.LogPerformanceMetric
    @ProcedureName NVARCHAR(100),
    @OperationType NVARCHAR(50),
    @ExecutionTimeMs INT,
    @RowsAffected INT = 0,
    @Parameters NVARCHAR(MAX) = NULL,
    @Success BIT = 1,
    @ErrorMessage NVARCHAR(500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Only log if monitoring is enabled
    IF dbo.GetConfigValue('Monitoring.EnableMetrics') = '1'
    BEGIN
        BEGIN TRY
            INSERT INTO dbo.PerformanceMetrics (
                ProcedureName, OperationType, ExecutionTimeMs, RowsAffected,
                Parameters, Success, ErrorMessage
            )
            VALUES (
                @ProcedureName, @OperationType, @ExecutionTimeMs, @RowsAffected,
                @Parameters, @Success, @ErrorMessage
            );
        END TRY
        BEGIN CATCH
            -- Silently handle performance logging failures
        END CATCH
    END
END;
GO

-- Audit Log Cleanup Procedure
CREATE PROCEDURE dbo.CleanupAuditLogs
    @RetentionDays INT = NULL,
    @BatchSize INT = 5000
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @ActualRetentionDays INT = ISNULL(@RetentionDays, CAST(dbo.GetConfigValue('Audit.RetentionDays') AS INT));
    DECLARE @CutoffDate DATETIME2(7) = DATEADD(DAY, -@ActualRetentionDays, GETUTCDATE());
    DECLARE @TotalDeleted INT = 0;
    DECLARE @BatchDeleted INT = 1;
    
    WHILE @BatchDeleted > 0
    BEGIN
        DELETE TOP (@BatchSize)
        FROM dbo.AuditLog
        WHERE CreatedAt < @CutoffDate;
        
        SET @BatchDeleted = @@ROWCOUNT;
        SET @TotalDeleted = @TotalDeleted + @BatchDeleted;
        
        -- Brief pause between batches to avoid blocking
        IF @BatchDeleted > 0
            WAITFOR DELAY '00:00:01';
    END
    
    -- Cleanup performance metrics
    SET @BatchDeleted = 1;
    WHILE @BatchDeleted > 0
    BEGIN
        DELETE TOP (@BatchSize)
        FROM dbo.PerformanceMetrics
        WHERE CreatedAt < @CutoffDate;
        
        SET @BatchDeleted = @@ROWCOUNT;
        SET @TotalDeleted = @TotalDeleted + @BatchDeleted;
        
        IF @BatchDeleted > 0
            WAITFOR DELAY '00:00:01';
    END
    
    -- Cleanup error logs (shorter retention)
    DELETE FROM dbo.ErrorLog
    WHERE CreatedAt < DATEADD(DAY, -30, GETUTCDATE());
    
    SET @TotalDeleted = @TotalDeleted + @@ROWCOUNT;
    
    SELECT @TotalDeleted AS TotalRecordsDeleted, 'Cleanup completed successfully' AS Message;
END;
GO

-- ============================================================================
-- INPUT VALIDATION PROCEDURES
-- ============================================================================

-- Drop existing validation procedures
IF OBJECT_ID('dbo.ValidatePhoneNumber', 'P') IS NOT NULL DROP PROCEDURE dbo.ValidatePhoneNumber;
IF OBJECT_ID('dbo.ValidateIpAddress', 'P') IS NOT NULL DROP PROCEDURE dbo.ValidateIpAddress;
IF OBJECT_ID('dbo.ValidateGuid', 'P') IS NOT NULL DROP PROCEDURE dbo.ValidateGuid;
GO

-- Phone Number Validation
CREATE PROCEDURE dbo.ValidatePhoneNumber
    @PhoneNumber NVARCHAR(18),
    @IsValid BIT OUTPUT,
    @ErrorMessage NVARCHAR(255) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET @IsValid = 0;
    SET @ErrorMessage = '';
    
    -- Check for null or empty
    IF @PhoneNumber IS NULL OR LEN(TRIM(@PhoneNumber)) = 0
    BEGIN
        SET @ErrorMessage = 'Phone number cannot be null or empty';
        RETURN;
    END
    
    -- Check length
    IF LEN(@PhoneNumber) < 10 OR LEN(@PhoneNumber) > 18
    BEGIN
        SET @ErrorMessage = 'Phone number must be between 10 and 18 characters';
        RETURN;
    END
    
    -- Check for valid characters (digits, +, -, (, ), space)
    IF @PhoneNumber LIKE '%[^0-9+\-() ]%'
    BEGIN
        SET @ErrorMessage = 'Phone number contains invalid characters';
        RETURN;
    END
    
    -- Must start with + or digit
    IF LEFT(@PhoneNumber, 1) NOT LIKE '[+0-9]'
    BEGIN
        SET @ErrorMessage = 'Phone number must start with + or digit';
        RETURN;
    END
    
    SET @IsValid = 1;
END;
GO

-- IP Address Validation
CREATE PROCEDURE dbo.ValidateIpAddress
    @IpAddress NVARCHAR(45),
    @IsValid BIT OUTPUT,
    @ErrorMessage NVARCHAR(255) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET @IsValid = 0;
    SET @ErrorMessage = '';
    
    -- Allow null IP addresses
    IF @IpAddress IS NULL
    BEGIN
        SET @IsValid = 1;
        RETURN;
    END
    
    -- Basic IPv4 validation (simplified)
    IF @IpAddress LIKE '[0-9]%.[0-9]%.[0-9]%.[0-9]%'
       AND @IpAddress NOT LIKE '%[^0-9.]%'
       AND LEN(@IpAddress) - LEN(REPLACE(@IpAddress, '.', '')) = 3
    BEGIN
        SET @IsValid = 1;
        RETURN;
    END
    
    -- Basic IPv6 validation (simplified)
    IF @IpAddress LIKE '%:%' AND LEN(@IpAddress) <= 45
    BEGIN
        SET @IsValid = 1;
        RETURN;
    END
    
    SET @ErrorMessage = 'Invalid IP address format';
END;
GO

-- GUID Validation
CREATE PROCEDURE dbo.ValidateGuid
    @GuidValue UNIQUEIDENTIFIER,
    @IsValid BIT OUTPUT,
    @ErrorMessage NVARCHAR(255) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET @IsValid = 0;
    SET @ErrorMessage = '';
    
    IF @GuidValue IS NULL OR @GuidValue = '00000000-0000-0000-0000-000000000000'
    BEGIN
        SET @ErrorMessage = 'GUID cannot be null or empty';
        RETURN;
    END
    
    SET @IsValid = 1;
END;
GO

-- ============================================================================
-- CIRCUIT BREAKER INFRASTRUCTURE
-- ============================================================================

-- Drop existing circuit breaker objects
IF OBJECT_ID('dbo.UpdateCircuitBreakerState', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateCircuitBreakerState;
IF OBJECT_ID('dbo.GetCircuitBreakerState', 'P') IS NOT NULL DROP PROCEDURE dbo.GetCircuitBreakerState;
IF OBJECT_ID('dbo.CircuitBreakerStates', 'U') IS NOT NULL DROP TABLE dbo.CircuitBreakerStates;
GO

-- Circuit Breaker States Table
CREATE TABLE dbo.CircuitBreakerStates (
    ServiceName NVARCHAR(100) PRIMARY KEY,
    State NVARCHAR(20) NOT NULL DEFAULT 'Closed', -- Closed, Open, HalfOpen
    FailureCount INT NOT NULL DEFAULT 0,
    SuccessCount INT NOT NULL DEFAULT 0,
    LastFailureAt DATETIME2(7),
    LastSuccessAt DATETIME2(7),
    NextRetryAt DATETIME2(7),
    FailureThreshold INT NOT NULL DEFAULT 5,
    SuccessThreshold INT NOT NULL DEFAULT 3,
    TimeoutMinutes INT NOT NULL DEFAULT 1,
    CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
    UpdatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
    CONSTRAINT CHK_CircuitBreakerState CHECK (State IN ('Closed', 'Open', 'HalfOpen'))
);

-- Insert default circuit breaker configurations
INSERT INTO dbo.CircuitBreakerStates (ServiceName, FailureThreshold, SuccessThreshold, TimeoutMinutes) VALUES
('AuthenticationService', 5, 3, 1),
('MembershipService', 5, 3, 1),
('VerificationFlowService', 10, 5, 2),
('OtpService', 10, 5, 1),
('PhoneNumberService', 3, 2, 1);
GO

COMMIT TRANSACTION;
GO

PRINT '✅ Production infrastructure tables and procedures created successfully.';
PRINT '   - System Configuration Management';
PRINT '   - Comprehensive Audit and Logging';
PRINT '   - Input Validation Procedures';
PRINT '   - Circuit Breaker Infrastructure';
GO