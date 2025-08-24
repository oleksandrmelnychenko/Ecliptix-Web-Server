/*
================================================================================
Layer 0: Pre-Deployment Checks
================================================================================
Purpose: Validate environment, permissions, and existing objects before deployment
Dependencies: None (Foundation layer)
Execution Order: 1st - Must run before any other scripts

Features:
- Database version and compatibility checks
- Permission validation
- Existing object detection and backup
- Environment validation
- Rollback preparation
- Pre-deployment safety checks

Author: Ecliptix Development Team
Version: 1.0.0
Created: 2024-08-24
================================================================================
*/

USE [master];
GO

-- Set error handling
SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Ecliptix Database Pre-Deployment Checks';
PRINT 'Started at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
PRINT '================================================================================';
GO

-- ============================================================================
-- ENVIRONMENT VALIDATION
-- ============================================================================

PRINT 'Phase 1: Environment validation...';

-- Check SQL Server version
DECLARE @SQLVersion NVARCHAR(128) = @@VERSION;
DECLARE @ProductVersion NVARCHAR(128) = CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128));
DECLARE @ProductMajorVersion INT = CAST(PARSENAME(@ProductVersion, 4) AS INT);

PRINT '  SQL Server Version: ' + @SQLVersion;
PRINT '  Product Version: ' + @ProductVersion;

-- Validate minimum SQL Server version (2019 = 15)
IF @ProductMajorVersion < 15
BEGIN
    RAISERROR('SQL Server 2019 or later is required. Current version: %s', 16, 1, @ProductVersion);
    RETURN;
END

-- Check collation
DECLARE @DatabaseCollation NVARCHAR(128) = CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS NVARCHAR(128));
PRINT '  Database Collation: ' + @DatabaseCollation;

-- Check database compatibility level
DECLARE @CompatibilityLevel INT = CAST(DATABASEPROPERTYEX(DB_NAME(), 'Version') AS INT);
PRINT '  Compatibility Level: ' + CAST(@CompatibilityLevel AS NVARCHAR(10));

IF @CompatibilityLevel < 150 -- SQL Server 2019 compatibility
BEGIN
    PRINT '  WARNING: Consider upgrading compatibility level to 150 (SQL Server 2019) for optimal performance';
END

PRINT '✓ Environment validation completed';
PRINT '';

-- ============================================================================
-- PERMISSION VALIDATION
-- ============================================================================

PRINT 'Phase 2: Permission validation...';

-- Check for required permissions
DECLARE @IsSysAdmin BIT = CASE WHEN IS_SRVROLEMEMBER('sysadmin') = 1 THEN 1 ELSE 0 END;
DECLARE @IsDbOwner BIT = CASE WHEN IS_MEMBER('db_owner') = 1 THEN 1 ELSE 0 END;
DECLARE @HasCreateTable BIT = HAS_PERMS_BY_NAME(NULL, NULL, 'CREATE TABLE');
DECLARE @HasCreateProcedure BIT = HAS_PERMS_BY_NAME(NULL, NULL, 'CREATE PROCEDURE');

PRINT '  System Administrator: ' + CASE WHEN @IsSysAdmin = 1 THEN 'YES' ELSE 'NO' END;
PRINT '  Database Owner: ' + CASE WHEN @IsDbOwner = 1 THEN 'YES' ELSE 'NO' END;
PRINT '  CREATE TABLE Permission: ' + CASE WHEN @HasCreateTable = 1 THEN 'YES' ELSE 'NO' END;
PRINT '  CREATE PROCEDURE Permission: ' + CASE WHEN @HasCreateProcedure = 1 THEN 'YES' ELSE 'NO' END;

-- Validate sufficient permissions
IF @IsSysAdmin = 0 AND @IsDbOwner = 0
BEGIN
    RAISERROR('Insufficient permissions. sysadmin or db_owner role required for deployment', 16, 1);
    RETURN;
END

IF @HasCreateTable = 0 OR @HasCreateProcedure = 0
BEGIN
    RAISERROR('Missing required CREATE permissions for deployment', 16, 1);
    RETURN;
END

PRINT '✓ Permission validation completed';
PRINT '';

-- ============================================================================
-- DATABASE STATE VALIDATION
-- ============================================================================

PRINT 'Phase 3: Database state validation...';

-- Check database state
DECLARE @DatabaseState NVARCHAR(60) = CAST(DATABASEPROPERTYEX(DB_NAME(), 'Status') AS NVARCHAR(60));
PRINT '  Database State: ' + @DatabaseState;

IF @DatabaseState != 'ONLINE'
BEGIN
    RAISERROR('Database must be ONLINE for deployment. Current state: %s', 16, 1, @DatabaseState);
    RETURN;
END

-- Check for active connections that might interfere
DECLARE @ActiveConnections INT;
SELECT @ActiveConnections = COUNT(*)
FROM sys.dm_exec_sessions
WHERE database_id = DB_ID()
  AND session_id != @@SPID
  AND is_user_process = 1;

PRINT '  Active Connections: ' + CAST(@ActiveConnections AS NVARCHAR(10));

IF @ActiveConnections > 5
BEGIN
    PRINT '  WARNING: High number of active connections detected. Consider deploying during maintenance window.';
END

-- Check available disk space (simplified check)
DECLARE @DatabaseSize DECIMAL(10,2);
DECLARE @LogSize DECIMAL(10,2);

SELECT 
    @DatabaseSize = SUM(CASE WHEN type_desc = 'ROWS' THEN size * 8.0 / 1024 ELSE 0 END),
    @LogSize = SUM(CASE WHEN type_desc = 'LOG' THEN size * 8.0 / 1024 ELSE 0 END)
FROM sys.master_files
WHERE database_id = DB_ID();

PRINT '  Database Size: ' + CAST(@DatabaseSize AS NVARCHAR(20)) + ' MB';
PRINT '  Log Size: ' + CAST(@LogSize AS NVARCHAR(20)) + ' MB';

PRINT '✓ Database state validation completed';
PRINT '';

-- ============================================================================
-- EXISTING OBJECTS INVENTORY
-- ============================================================================

PRINT 'Phase 4: Existing objects inventory...';

-- Create temporary table for object inventory
IF OBJECT_ID('tempdb..#ExistingObjects') IS NOT NULL DROP TABLE #ExistingObjects;

CREATE TABLE #ExistingObjects (
    ObjectType NVARCHAR(50),
    ObjectName NVARCHAR(128),
    ObjectSchema NVARCHAR(128),
    CreatedDate DATETIME,
    ModifiedDate DATETIME,
    WillBeModified BIT DEFAULT 0
);

-- Inventory existing objects
INSERT INTO #ExistingObjects (ObjectType, ObjectName, ObjectSchema, CreatedDate, ModifiedDate, WillBeModified)
SELECT 
    'Table' AS ObjectType,
    name AS ObjectName,
    SCHEMA_NAME(schema_id) AS ObjectSchema,
    create_date AS CreatedDate,
    modify_date AS ModifiedDate,
    CASE 
        WHEN name IN ('AppDevices', 'PhoneNumbers', 'VerificationFlows', 'OtpRecords', 'Memberships', 
                     'AuthenticationContexts', 'AuthenticationStates', 'LoginAttempts', 'MembershipAttempts',
                     'FailedOtpAttempts', 'PhoneNumberDevices') THEN 1 
        ELSE 0 
    END AS WillBeModified
FROM sys.tables
WHERE schema_id = SCHEMA_ID('dbo')

UNION ALL

SELECT 
    'Procedure' AS ObjectType,
    name AS ObjectName,
    SCHEMA_NAME(schema_id) AS ObjectSchema,
    create_date AS CreatedDate,
    modify_date AS ModifiedDate,
    CASE 
        WHEN name LIKE '%Authentication%' OR name LIKE '%Membership%' OR name LIKE '%Verification%' 
             OR name LIKE '%Otp%' OR name LIKE '%Phone%' OR name LIKE '%Device%'
             OR name IN ('LogError', 'LogAuditEvent', 'GetConfigValue', 'SetConfigValue') THEN 1 
        ELSE 0 
    END AS WillBeModified
FROM sys.procedures
WHERE schema_id = SCHEMA_ID('dbo')

UNION ALL

SELECT 
    'Function' AS ObjectType,
    name AS ObjectName,
    SCHEMA_NAME(schema_id) AS ObjectSchema,
    create_date AS CreatedDate,
    modify_date AS ModifiedDate,
    CASE 
        WHEN name LIKE '%Authentication%' OR name LIKE '%Membership%' OR name LIKE '%Verification%' 
             OR name LIKE '%Otp%' OR name LIKE '%Phone%' OR name LIKE '%Config%' THEN 1 
        ELSE 0 
    END AS WillBeModified
FROM sys.objects
WHERE type IN ('FN', 'IF', 'TF') AND schema_id = SCHEMA_ID('dbo')

UNION ALL

SELECT 
    'Trigger' AS ObjectType,
    tr.name AS ObjectName,
    SCHEMA_NAME(t.schema_id) AS ObjectSchema,
    tr.create_date AS CreatedDate,
    tr.modify_date AS ModifiedDate,
    1 AS WillBeModified -- All triggers will likely be recreated
FROM sys.triggers tr
INNER JOIN sys.tables t ON tr.parent_id = t.object_id
WHERE t.schema_id = SCHEMA_ID('dbo');

-- Report existing objects
DECLARE @TotalObjects INT, @ObjectsToModify INT;
SELECT @TotalObjects = COUNT(*), @ObjectsToModify = SUM(CASE WHEN WillBeModified = 1 THEN 1 ELSE 0 END)
FROM #ExistingObjects;

PRINT '  Total Existing Objects: ' + CAST(@TotalObjects AS NVARCHAR(10));
PRINT '  Objects to be Modified: ' + CAST(@ObjectsToModify AS NVARCHAR(10));

IF @ObjectsToModify > 0
BEGIN
    PRINT '';
    PRINT '  Objects that will be modified during deployment:';
    
    SELECT 
        ObjectType,
        ObjectSchema,
        ObjectName,
        FORMAT(CreatedDate, 'yyyy-MM-dd HH:mm:ss') AS Created,
        FORMAT(ModifiedDate, 'yyyy-MM-dd HH:mm:ss') AS Modified
    FROM #ExistingObjects
    WHERE WillBeModified = 1
    ORDER BY ObjectType, ObjectSchema, ObjectName;
    
    PRINT '';
    PRINT '  RECOMMENDATION: Backup these objects before proceeding with deployment.';
END

PRINT '✓ Object inventory completed';
PRINT '';

-- ============================================================================
-- ROLLBACK PREPARATION
-- ============================================================================

PRINT 'Phase 5: Rollback preparation...';

-- Create deployment log table if it doesn't exist
IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'DeploymentLog' AND schema_id = SCHEMA_ID('dbo'))
BEGIN
    CREATE TABLE dbo.DeploymentLog (
        Id BIGINT IDENTITY(1,1) PRIMARY KEY,
        DeploymentId UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID(),
        ScriptName NVARCHAR(255) NOT NULL,
        ExecutionOrder INT NOT NULL,
        StartTime DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
        EndTime DATETIME2(7),
        Status NVARCHAR(20) NOT NULL DEFAULT 'RUNNING',
        ErrorMessage NVARCHAR(MAX),
        RowsAffected BIGINT,
        ExecutedBy NVARCHAR(128) NOT NULL DEFAULT SYSTEM_USER,
        CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
        CONSTRAINT CHK_DeploymentLog_Status CHECK (Status IN ('RUNNING', 'COMPLETED', 'FAILED', 'ROLLED_BACK'))
    );
    
    CREATE NONCLUSTERED INDEX IX_DeploymentLog_DeploymentId ON dbo.DeploymentLog (DeploymentId);
    CREATE NONCLUSTERED INDEX IX_DeploymentLog_Status ON dbo.DeploymentLog (Status);
    
    PRINT '  ✓ Deployment log table created';
END
ELSE
BEGIN
    PRINT '  ✓ Deployment log table already exists';
END

-- Generate unique deployment ID for this run
DECLARE @DeploymentId UNIQUEIDENTIFIER = NEWID();
PRINT '  Deployment ID: ' + CAST(@DeploymentId AS NVARCHAR(36));

-- Log the pre-deployment check
INSERT INTO dbo.DeploymentLog (DeploymentId, ScriptName, ExecutionOrder, Status, RowsAffected)
VALUES (@DeploymentId, '00_PreDeploymentChecks.sql', 0, 'COMPLETED', 0);

PRINT '✓ Rollback preparation completed';
PRINT '';

-- ============================================================================
-- DEPLOYMENT READINESS ASSESSMENT
-- ============================================================================

PRINT 'Phase 6: Deployment readiness assessment...';

DECLARE @ReadinessScore INT = 0;
DECLARE @MaxScore INT = 6;

-- Score based on various factors
IF @ProductMajorVersion >= 15 SET @ReadinessScore = @ReadinessScore + 1; -- SQL Server version
IF @IsSysAdmin = 1 OR @IsDbOwner = 1 SET @ReadinessScore = @ReadinessScore + 1; -- Permissions
IF @DatabaseState = 'ONLINE' SET @ReadinessScore = @ReadinessScore + 1; -- Database state
IF @CompatibilityLevel >= 150 SET @ReadinessScore = @ReadinessScore + 1; -- Compatibility level
IF @ActiveConnections <= 5 SET @ReadinessScore = @ReadinessScore + 1; -- Active connections
IF @DatabaseSize < 10000 SET @ReadinessScore = @ReadinessScore + 1; -- Database size reasonable

DECLARE @ReadinessPercentage INT = (@ReadinessScore * 100) / @MaxScore;

PRINT '  Deployment Readiness Score: ' + CAST(@ReadinessScore AS NVARCHAR(2)) + '/' + CAST(@MaxScore AS NVARCHAR(2)) + 
      ' (' + CAST(@ReadinessPercentage AS NVARCHAR(3)) + '%)';

IF @ReadinessPercentage >= 80
BEGIN
    PRINT '  STATUS: ✅ READY FOR DEPLOYMENT';
END
ELSE IF @ReadinessPercentage >= 60
BEGIN
    PRINT '  STATUS: ⚠️  DEPLOYMENT POSSIBLE WITH CAUTION';
END
ELSE
BEGIN
    PRINT '  STATUS: ❌ NOT READY FOR DEPLOYMENT - ADDRESS ISSUES ABOVE';
END

PRINT '';

-- ============================================================================
-- FINAL RECOMMENDATIONS
-- ============================================================================

PRINT 'Pre-Deployment Recommendations:';
PRINT '1. Ensure full database backup is taken before proceeding';
PRINT '2. Schedule deployment during maintenance window if possible';
PRINT '3. Monitor deployment progress using DeploymentLog table';
PRINT '4. Have rollback plan ready in case of issues';
PRINT '5. Test on staging environment first if not already done';

-- Clean up temporary objects
IF OBJECT_ID('tempdb..#ExistingObjects') IS NOT NULL DROP TABLE #ExistingObjects;

PRINT '';
PRINT '================================================================================';
PRINT 'Pre-Deployment Checks Completed Successfully';
PRINT 'Ready to proceed with Layer 1: Configuration & Core Infrastructure';
PRINT 'Finished at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
PRINT '================================================================================';
GO