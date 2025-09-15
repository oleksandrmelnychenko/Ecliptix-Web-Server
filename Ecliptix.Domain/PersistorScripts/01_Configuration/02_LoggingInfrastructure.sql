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

USE [EcliptixMemberships];
SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Layer 1.2: Logging Infrastructure';
PRINT 'Started at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
PRINT '================================================================================';
GO

-- ============================================================================
-- STEP 1: CREATE TABLES
-- ============================================================================

-- ERROR LOG TABLE
IF OBJECT_ID('dbo.ErrorLog','U') IS NOT NULL DROP TABLE dbo.ErrorLog;
GO
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
CREATE NONCLUSTERED INDEX IX_ErrorLog_ErrorNumber ON dbo.ErrorLog (ErrorNumber);
CREATE NONCLUSTERED INDEX IX_ErrorLog_UserId_CreatedAt ON dbo.ErrorLog (UserId, CreatedAt) WHERE UserId IS NOT NULL;
GO
PRINT '✓ ErrorLog table created successfully';

-- AUDIT LOG TABLE
IF OBJECT_ID('dbo.AuditLog','U') IS NOT NULL DROP TABLE dbo.AuditLog;
GO
CREATE TABLE dbo.AuditLog (
    Id BIGINT IDENTITY(1,1) PRIMARY KEY,
    TableName NVARCHAR(100) NOT NULL,
    OperationType NVARCHAR(20) NOT NULL,
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
        CHECK (OperationType IN ('INSERT','UPDATE','DELETE','SELECT','LOGIN_SUCCESS','LOGIN_FAILED',
        'LOGIN_BLOCKED','ACCOUNT_LOCKED','SUSPICIOUS_ACTIVITY','STATUS_CHANGE','ACTIVATION_CHANGE',
        'DEVICE_ASSOCIATION','OTP_CREATION_FAILED','MAX_OTP_ATTEMPTS_REACHED','INVALID_DEVICE_ASSOCIATION',
        'LOCKOUT_EXPIRED','VALIDATE','EXPIRE','CLEANUP','DEPLOYMENT_COMPLETE'))
);
CREATE NONCLUSTERED INDEX IX_AuditLog_CreatedAt ON dbo.AuditLog (CreatedAt);
CREATE NONCLUSTERED INDEX IX_AuditLog_TableName_CreatedAt ON dbo.AuditLog (TableName, CreatedAt);
CREATE NONCLUSTERED INDEX IX_AuditLog_RecordId ON dbo.AuditLog (RecordId);
CREATE NONCLUSTERED INDEX IX_AuditLog_UserId_CreatedAt ON dbo.AuditLog (UserId, CreatedAt) WHERE UserId IS NOT NULL;
CREATE NONCLUSTERED INDEX IX_AuditLog_OperationType_CreatedAt ON dbo.AuditLog (OperationType, CreatedAt);
CREATE NONCLUSTERED INDEX IX_AuditLog_Success_CreatedAt ON dbo.AuditLog (Success, CreatedAt);
GO
PRINT '✓ AuditLog table created successfully';

-- PERFORMANCE METRICS TABLE
IF OBJECT_ID('dbo.PerformanceMetrics','U') IS NOT NULL DROP TABLE dbo.PerformanceMetrics;
GO
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
CREATE NONCLUSTERED INDEX IX_PerformanceMetrics_OperationType_CreatedAt ON dbo.PerformanceMetrics (OperationType, CreatedAt);
CREATE NONCLUSTERED INDEX IX_PerformanceMetrics_ExecutionTimeMs ON dbo.PerformanceMetrics (ExecutionTimeMs) WHERE ExecutionTimeMs > 1000;
GO
PRINT '✓ PerformanceMetrics table created successfully';

-- ============================================================================
-- STEP 2: CREATE PROCEDURES
-- ============================================================================

-- LogError
IF OBJECT_ID('dbo.LogError','P') IS NOT NULL DROP PROCEDURE dbo.LogError;
GO
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
       -- silent fail
    END CATCH
END;
GO
PRINT '✓ LogError procedure created successfully';

-- LogAuditEvent
IF OBJECT_ID('dbo.LogAuditEvent','P') IS NOT NULL DROP PROCEDURE dbo.LogAuditEvent;
GO
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
        -- silent fail
    END CATCH
END;
GO
PRINT '✓ LogAuditEvent procedure created successfully';

-- LogPerformanceMetric
IF OBJECT_ID('dbo.LogPerformanceMetric','P') IS NOT NULL DROP PROCEDURE dbo.LogPerformanceMetric;
GO
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
    IF dbo.GetConfigValue('Monitoring.EnableMetrics')='1'
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
            -- silent fail
        END CATCH
    END
END;
GO
PRINT '✓ LogPerformanceMetric procedure created successfully';

-- Cleanup Procedure
IF OBJECT_ID('dbo.CleanupAuditLogs','P') IS NOT NULL DROP PROCEDURE dbo.CleanupAuditLogs;
GO
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
        SET @TotalDeleted += @BatchDeleted;
        IF @BatchDeleted>0 WAITFOR DELAY '00:00:01';
    END

    SET @BatchDeleted=1;
    WHILE @BatchDeleted>0
    BEGIN
        DELETE TOP (@BatchSize)
        FROM dbo.PerformanceMetrics
        WHERE CreatedAt < @CutoffDate;
        SET @BatchDeleted=@@ROWCOUNT;
        SET @TotalDeleted += @BatchDeleted;
        IF @BatchDeleted>0 WAITFOR DELAY '00:00:01';
    END

    DELETE FROM dbo.ErrorLog
    WHERE CreatedAt < DATEADD(DAY,-30,GETUTCDATE());
    SET @TotalDeleted += @@ROWCOUNT;

    SELECT @TotalDeleted AS TotalRecordsDeleted, 'Cleanup completed successfully' AS Message;
END;
GO
PRINT '✓ CleanupAuditLogs procedure created successfully';

-- ============================================================================
-- STEP 3: VALIDATION (outside transaction)
-- ============================================================================

DECLARE @ErrorRows INT = 0, @AuditRows INT = 0, @MetricsRows INT = 0;

EXEC dbo.LogError @ProcedureName='LoggingInfrastructure_Validation',
                   @ErrorMessage='Test error log entry - deployment validation',
                   @ErrorNumber = 50000,
                   @ErrorSeverity = 16,
                   @ErrorState = 1;

SELECT @ErrorRows=COUNT(*) FROM dbo.ErrorLog WHERE ProcedureName='LoggingInfrastructure_Validation';

EXEC dbo.LogAuditEvent @TableName='DeploymentValidation',
                       @OperationType='DEPLOYMENT_COMPLETE',
                       @RecordId='LoggingInfrastructure',
                       @ApplicationContext='Layer1.2_Validation',
                       @Success=1;
SELECT @AuditRows=COUNT(*) FROM dbo.AuditLog WHERE ApplicationContext='Layer1.2_Validation';

EXEC dbo.LogPerformanceMetric @ProcedureName='LoggingInfrastructure_Validation',
                              @OperationType='DEPLOYMENT_TEST',
                              @ExecutionTimeMs=100,
                              @RowsAffected=3,
                              @Success=1;
SELECT @MetricsRows=COUNT(*) FROM dbo.PerformanceMetrics WHERE ProcedureName='LoggingInfrastructure_Validation';

IF @ErrorRows=0 OR @AuditRows=0 OR @MetricsRows=0
    RAISERROR('Logging validation failed. Error: %d, Audit: %d, Metrics: %d',16,1,@ErrorRows,@AuditRows,@MetricsRows);

PRINT '✓ Logging infrastructure validation completed successfully';
GO

PRINT '================================================================================';
PRINT 'Layer 1.2: Logging Infrastructure Completed Successfully';
PRINT 'Tables created: 3 (ErrorLog, AuditLog, PerformanceMetrics)';
PRINT 'Procedures created: 4 (LogError, LogAuditEvent, LogPerformanceMetric, CleanupAuditLogs)';
PRINT 'Next: Layer 1.3 - Validation Framework';
PRINT 'Finished at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
PRINT '================================================================================';
GO
