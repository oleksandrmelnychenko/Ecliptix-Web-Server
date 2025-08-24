/*
================================================================================
Layer 1.2: Logging Infrastructure
================================================================================
Purpose: Comprehensive audit logging, error tracking, and performance monitoring
Dependencies: 01_SystemConfiguration.sql
Execution Order: 3rd - Core logging infrastructure for all operations

Features:
- ErrorLog table and procedures for structured error logging
- AuditLog table and procedures for compliance audit trails
- PerformanceMetrics table and procedures for operation monitoring
- Automated cleanup procedures for log management
- Configurable logging levels and retention policies

Author: Ecliptix Development Team
Version: 1.0.0
Created: 2024-08-24
================================================================================
*/

USE [EcliptixDatabase]; -- Replace with your actual database name
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Layer 1.2: Logging Infrastructure';
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
VALUES (@DeploymentId, '02_LoggingInfrastructure.sql', 2, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- ERROR LOG TABLE
    -- ============================================================================
    
    PRINT 'Creating ErrorLog table...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.ErrorLog', 'U') IS NOT NULL 
        DROP TABLE dbo.ErrorLog;
    
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
    
    -- Create indexes
    CREATE NONCLUSTERED INDEX IX_ErrorLog_CreatedAt 
        ON dbo.ErrorLog (CreatedAt);
    CREATE NONCLUSTERED INDEX IX_ErrorLog_ProcedureName_CreatedAt 
        ON dbo.ErrorLog (ProcedureName, CreatedAt);
    CREATE NONCLUSTERED INDEX IX_ErrorLog_ErrorNumber 
        ON dbo.ErrorLog (ErrorNumber);
    CREATE NONCLUSTERED INDEX IX_ErrorLog_UserId_CreatedAt 
        ON dbo.ErrorLog (UserId, CreatedAt) WHERE UserId IS NOT NULL;
    
    PRINT '✓ ErrorLog table created successfully';
    
    -- ============================================================================
    -- AUDIT LOG TABLE
    -- ============================================================================
    
    PRINT 'Creating AuditLog table...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.AuditLog', 'U') IS NOT NULL 
        DROP TABLE dbo.AuditLog;
    
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
        CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
        CONSTRAINT CHK_AuditLog_OperationType 
            CHECK (OperationType IN ('INSERT', 'UPDATE', 'DELETE', 'SELECT', 'LOGIN_SUCCESS', 'LOGIN_FAILED', 
                                    'LOGIN_BLOCKED', 'ACCOUNT_LOCKED', 'SUSPICIOUS_ACTIVITY', 'STATUS_CHANGE', 
                                    'ACTIVATION_CHANGE', 'DEVICE_ASSOCIATION', 'OTP_CREATION_FAILED', 
                                    'MAX_OTP_ATTEMPTS_REACHED', 'INVALID_DEVICE_ASSOCIATION', 'LOCKOUT_EXPIRED', 
                                    'VALIDATE', 'EXPIRE', 'CLEANUP', 'DEPLOYMENT_COMPLETE'))
    );
    
    -- Create indexes
    CREATE NONCLUSTERED INDEX IX_AuditLog_CreatedAt 
        ON dbo.AuditLog (CreatedAt);
    CREATE NONCLUSTERED INDEX IX_AuditLog_TableName_CreatedAt 
        ON dbo.AuditLog (TableName, CreatedAt);
    CREATE NONCLUSTERED INDEX IX_AuditLog_RecordId 
        ON dbo.AuditLog (RecordId);
    CREATE NONCLUSTERED INDEX IX_AuditLog_UserId_CreatedAt 
        ON dbo.AuditLog (UserId, CreatedAt) WHERE UserId IS NOT NULL;
    CREATE NONCLUSTERED INDEX IX_AuditLog_OperationType_CreatedAt 
        ON dbo.AuditLog (OperationType, CreatedAt);
    CREATE NONCLUSTERED INDEX IX_AuditLog_Success_CreatedAt 
        ON dbo.AuditLog (Success, CreatedAt);
    
    PRINT '✓ AuditLog table created successfully';
    
    -- ============================================================================
    -- PERFORMANCE METRICS TABLE
    -- ============================================================================
    
    PRINT 'Creating PerformanceMetrics table...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.PerformanceMetrics', 'U') IS NOT NULL 
        DROP TABLE dbo.PerformanceMetrics;
    
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
    
    -- Create indexes
    CREATE NONCLUSTERED INDEX IX_PerformanceMetrics_CreatedAt 
        ON dbo.PerformanceMetrics (CreatedAt);
    CREATE NONCLUSTERED INDEX IX_PerformanceMetrics_ProcedureName_CreatedAt 
        ON dbo.PerformanceMetrics (ProcedureName, CreatedAt);
    CREATE NONCLUSTERED INDEX IX_PerformanceMetrics_OperationType_CreatedAt 
        ON dbo.PerformanceMetrics (OperationType, CreatedAt);
    CREATE NONCLUSTERED INDEX IX_PerformanceMetrics_ExecutionTimeMs 
        ON dbo.PerformanceMetrics (ExecutionTimeMs) WHERE ExecutionTimeMs > 1000;
    
    PRINT '✓ PerformanceMetrics table created successfully';
    
    -- ============================================================================
    -- ERROR LOGGING PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating error logging procedures...';
    
    -- Drop existing procedures
    IF OBJECT_ID('dbo.LogError', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.LogError;
    
    EXEC ('
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
                @ProcedureName, 
                ISNULL(@ErrorNumber, ERROR_NUMBER()), 
                @ErrorMessage,
                ISNULL(@ErrorSeverity, ERROR_SEVERITY()), 
                ISNULL(@ErrorState, ERROR_STATE()),
                ISNULL(@ErrorLine, ERROR_LINE()), 
                @Parameters, 
                @UserId, 
                @SessionId, 
                @IpAddress, 
                @UserAgent
            );
        END TRY
        BEGIN CATCH
            -- If logging fails, we don''t want to break the main operation
            -- Could implement a fallback logging mechanism here (e.g., Windows Event Log)
        END CATCH
    END;
    ');
    
    PRINT '✓ LogError procedure created successfully';
    
    -- ============================================================================
    -- AUDIT LOGGING PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating audit logging procedures...';
    
    -- Drop existing procedures
    IF OBJECT_ID('dbo.LogAuditEvent', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.LogAuditEvent;
    
    EXEC ('
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
    ');
    
    PRINT '✓ LogAuditEvent procedure created successfully';
    
    -- ============================================================================
    -- PERFORMANCE METRICS PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating performance metrics procedures...';
    
    -- Drop existing procedures
    IF OBJECT_ID('dbo.LogPerformanceMetric', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.LogPerformanceMetric;
    
    EXEC ('
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
        IF dbo.GetConfigValue(''Monitoring.EnableMetrics'') = ''1''
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
    ');
    
    PRINT '✓ LogPerformanceMetric procedure created successfully';
    
    -- ============================================================================
    -- CLEANUP PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating log cleanup procedures...';
    
    -- Drop existing procedures
    IF OBJECT_ID('dbo.CleanupAuditLogs', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.CleanupAuditLogs;
    
    EXEC ('
    CREATE PROCEDURE dbo.CleanupAuditLogs
        @RetentionDays INT = NULL,
        @BatchSize INT = 5000
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @ActualRetentionDays INT = ISNULL(@RetentionDays, CAST(dbo.GetConfigValue(''Audit.RetentionDays'') AS INT));
        DECLARE @CutoffDate DATETIME2(7) = DATEADD(DAY, -@ActualRetentionDays, GETUTCDATE());
        DECLARE @TotalDeleted INT = 0;
        DECLARE @BatchDeleted INT = 1;
        
        -- Cleanup audit logs
        WHILE @BatchDeleted > 0
        BEGIN
            DELETE TOP (@BatchSize)
            FROM dbo.AuditLog
            WHERE CreatedAt < @CutoffDate;
            
            SET @BatchDeleted = @@ROWCOUNT;
            SET @TotalDeleted = @TotalDeleted + @BatchDeleted;
            
            -- Brief pause between batches to avoid blocking
            IF @BatchDeleted > 0
                WAITFOR DELAY ''00:00:01'';
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
                WAITFOR DELAY ''00:00:01'';
        END
        
        -- Cleanup error logs (shorter retention - 30 days)
        DELETE FROM dbo.ErrorLog
        WHERE CreatedAt < DATEADD(DAY, -30, GETUTCDATE());
        
        SET @TotalDeleted = @TotalDeleted + @@ROWCOUNT;
        
        SELECT @TotalDeleted AS TotalRecordsDeleted, ''Cleanup completed successfully'' AS Message;
    END;
    ');
    
    PRINT '✓ CleanupAuditLogs procedure created successfully';
    
    -- ============================================================================
    -- VALIDATION AND TESTING
    -- ============================================================================
    
    PRINT 'Validating logging infrastructure...';
    
    -- Test error logging
    EXEC dbo.LogError 
        @ProcedureName = 'LoggingInfrastructure_Validation',
        @ErrorMessage = 'Test error log entry - deployment validation';
    
    -- Test audit logging
    EXEC dbo.LogAuditEvent
        @TableName = 'DeploymentValidation',
        @OperationType = 'DEPLOYMENT_COMPLETE',
        @RecordId = 'LoggingInfrastructure',
        @ApplicationContext = 'Layer1.2_Validation',
        @Success = 1;
    
    -- Test performance logging
    EXEC dbo.LogPerformanceMetric
        @ProcedureName = 'LoggingInfrastructure_Validation',
        @OperationType = 'DEPLOYMENT_TEST',
        @ExecutionTimeMs = 100,
        @RowsAffected = 3,
        @Success = 1;
    
    -- Validate test entries were created
    DECLARE @ErrorCount INT, @AuditCount INT, @MetricsCount INT;
    
    SELECT @ErrorCount = COUNT(*) FROM dbo.ErrorLog WHERE ProcedureName = 'LoggingInfrastructure_Validation';
    SELECT @AuditCount = COUNT(*) FROM dbo.AuditLog WHERE ApplicationContext = 'Layer1.2_Validation';
    SELECT @MetricsCount = COUNT(*) FROM dbo.PerformanceMetrics WHERE ProcedureName = 'LoggingInfrastructure_Validation';
    
    IF @ErrorCount = 0 OR @AuditCount = 0 OR @MetricsCount = 0
    BEGIN
        RAISERROR('Logging validation failed. Error: %d, Audit: %d, Metrics: %d', 16, 1, @ErrorCount, @AuditCount, @MetricsCount);
    END
    
    PRINT '✓ Logging infrastructure validation completed successfully';
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = 3
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 1.2: Logging Infrastructure Completed Successfully';
    PRINT 'Tables created: 3 (ErrorLog, AuditLog, PerformanceMetrics)';
    PRINT 'Procedures created: 3 (LogError, LogAuditEvent, LogPerformanceMetric, CleanupAuditLogs)';
    PRINT 'Next: Layer 1.3 - Validation Framework';
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
    PRINT 'ERROR in Layer 1.2: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO