/*
================================================================================
Layer 7.2: Business Helper Functions and Procedures
================================================================================
Purpose: Helper functions and procedures for common business operations,
         reporting, and administrative tasks

Dependencies: 
- Layer 1: Configuration & Core Infrastructure (all files)
- Layer 2: Core Domain Tables (01_CoreDomainTables.sql)
- Layer 7.1: Business Views (01_BusinessViews.sql)

Version: 1.0.0
Author: Ecliptix Development Team
Created: 2024-08-24

Features:
- Business query helper functions
- Administrative utility procedures
- Reporting and analytics helpers
- Data cleanup and maintenance utilities
- Security analysis helpers

Functions and Procedures Created:
- fn_GetMembershipStatus (membership status lookup)
- fn_IsPhoneNumberActive (phone number activity check)
- sp_GetUserSummary (comprehensive user information)
- sp_CleanupExpiredData (maintenance procedure)
- sp_GenerateActivityReport (activity reporting)
================================================================================
*/

-- Log deployment start
INSERT INTO dbo.DeploymentLog (ScriptName, Status, StartTime, Message)
VALUES ('07_ViewsHelpers/02_BusinessHelpers.sql', 'RUNNING', GETUTCDATE(), 'Starting Business Helper Functions deployment');

DECLARE @DeploymentId BIGINT = SCOPE_IDENTITY();
DECLARE @ErrorMessage NVARCHAR(4000);
DECLARE @StartTime DATETIME2(7) = GETUTCDATE();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- Performance tracking
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'HELPER_DEPLOYMENT',
        @TableName = 'BusinessHelpers',
        @Duration = 0,
        @RowsAffected = 0,
        @AdditionalInfo = 'Starting Business Helper Functions deployment';

    PRINT '🚀 Deploying Business Helper Functions...';

    -- Drop existing functions and procedures if they exist
    IF OBJECT_ID('dbo.fn_GetMembershipStatus', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.fn_GetMembershipStatus;
    
    IF OBJECT_ID('dbo.fn_IsPhoneNumberActive', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.fn_IsPhoneNumberActive;
        
    IF OBJECT_ID('dbo.sp_GetUserSummary', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.sp_GetUserSummary;
        
    IF OBJECT_ID('dbo.sp_CleanupExpiredData', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.sp_CleanupExpiredData;
        
    IF OBJECT_ID('dbo.sp_GenerateActivityReport', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.sp_GenerateActivityReport;

    /*
    ================================================================================
    Function: fn_GetMembershipStatus
    Purpose: Get detailed membership status for a given phone number and device
    
    Parameters:
    - @PhoneNumberId: Phone number unique identifier
    - @AppDeviceId: Device unique identifier
    
    Returns: NVARCHAR(50) - Detailed membership status
    ================================================================================
    */
    PRINT '👤 Creating GetMembershipStatus function...';
    
        CREATE FUNCTION dbo.fn_GetMembershipStatus(
        @PhoneNumberId UNIQUEIDENTIFIER,
        @AppDeviceId UNIQUEIDENTIFIER
    )
    RETURNS NVARCHAR(50)
    AS
    BEGIN
        DECLARE @Status NVARCHAR(50) = 'No Membership';
        
        SELECT @Status = 
            CASE 
                WHEN m.Status = 'active' AND m.CreationStatus = 'passphrase_set' THEN 'Fully Active'
                WHEN m.Status = 'active' AND m.CreationStatus = 'secure_key_set' THEN 'Active - Key Set'
                WHEN m.Status = 'active' AND m.CreationStatus = 'otp_verified' THEN 'Active - OTP Only'
                WHEN m.Status = 'inactive' THEN 'Inactive'
                ELSE 'Unknown Status'
            END
        FROM dbo.Memberships m
        WHERE m.PhoneNumberId = @PhoneNumberId 
            AND m.AppDeviceId = @AppDeviceId
            AND m.IsDeleted = 0;
            
        RETURN @Status;
    END;

    /*
    ================================================================================
    Function: fn_IsPhoneNumberActive
    Purpose: Check if a phone number has any active memberships or verifications
    
    Parameters:
    - @PhoneNumber: Phone number string
    - @Region: Phone number region (optional)
    
    Returns: BIT - 1 if active, 0 if not active
    ================================================================================
    */
    PRINT '📞 Creating IsPhoneNumberActive function...';
    
        CREATE FUNCTION dbo.fn_IsPhoneNumberActive(
        @PhoneNumber NVARCHAR(18),
        @Region NVARCHAR(2) = NULL
    )
    RETURNS BIT
    AS
    BEGIN
        DECLARE @IsActive BIT = 0;
        DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
        
        -- Find the phone number record
        SELECT @PhoneNumberId = UniqueId
        FROM dbo.PhoneNumbers 
        WHERE PhoneNumber = @PhoneNumber 
            AND (@Region IS NULL OR Region = @Region)
            AND IsDeleted = 0;
            
        IF @PhoneNumberId IS NOT NULL
        BEGIN
            -- Check for active memberships
            IF EXISTS (
                SELECT 1 FROM dbo.Memberships 
                WHERE PhoneNumberId = @PhoneNumberId 
                    AND Status = 'active'
                    AND IsDeleted = 0
            )
                SET @IsActive = 1;
            
            -- Check for pending verifications
            ELSE IF EXISTS (
                SELECT 1 FROM dbo.VerificationFlows vf
                INNER JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
                WHERE pn.UniqueId = @PhoneNumberId
                    AND vf.Status = 'pending'
                    AND vf.ExpiresAt > GETUTCDATE()
                    AND vf.IsDeleted = 0
            )
                SET @IsActive = 1;
        END
            
        RETURN @IsActive;
    END;

    /*
    ================================================================================
    Procedure: sp_GetUserSummary
    Purpose: Get comprehensive user summary information for a phone number
    
    Parameters:
    - @PhoneNumber: Phone number to lookup
    - @Region: Phone number region (optional)
    
    Returns: Result set with user summary information
    ================================================================================
    */
    PRINT '📋 Creating GetUserSummary procedure...';
    
        CREATE PROCEDURE dbo.sp_GetUserSummary
        @PhoneNumber NVARCHAR(18),
        @Region NVARCHAR(2) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        BEGIN TRY
            -- Log performance start
            DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
            
            -- Main user summary query
            SELECT 
                'User Summary' AS ReportType,
                pn.PhoneNumber,
                pn.Region,
                pn.CreatedAt AS PhoneRegisteredAt,
                
                -- Membership information
                m.Status AS MembershipStatus,
                m.CreationStatus AS MembershipCreationStatus,
                m.CreatedAt AS MembershipCreatedAt,
                ad.DeviceType,
                ad.DeviceId,
                
                -- Recent activity
                (SELECT COUNT(*) FROM dbo.VerificationFlows vf2 
                 INNER JOIN dbo.PhoneNumbers pn2 ON vf2.PhoneNumberId = pn2.Id
                 WHERE pn2.UniqueId = pn.UniqueId 
                   AND vf2.CreatedAt >= DATEADD(DAY, -30, GETUTCDATE())) AS VerificationFlowsLast30Days,
                
                (SELECT COUNT(*) FROM dbo.LoginAttempts la 
                 WHERE la.PhoneNumber = pn.PhoneNumber 
                   AND la.Timestamp >= DATEADD(DAY, -30, GETUTCDATE())) AS LoginAttemptsLast30Days,
                
                -- Current status
                CASE 
                    WHEN ast.IsLocked = 1 AND ast.LockedUntil > GETUTCDATE() THEN 'Account Locked'
                    WHEN m.Status = 'active' THEN 'Active User'
                    WHEN m.Status = 'inactive' THEN 'Inactive User'
                    ELSE 'No Membership'
                END AS CurrentStatus
                
            FROM dbo.PhoneNumbers pn
            LEFT JOIN dbo.Memberships m ON pn.UniqueId = m.PhoneNumberId AND m.IsDeleted = 0
            LEFT JOIN dbo.AppDevices ad ON m.AppDeviceId = ad.UniqueId
            LEFT JOIN dbo.AuthenticationStates ast ON pn.UniqueId = ast.MobileNumberId
            WHERE pn.PhoneNumber = @PhoneNumber
                AND (@Region IS NULL OR pn.Region = @Region)
                AND pn.IsDeleted = 0;
            
            -- Active sessions information
            SELECT 
                'Active Sessions' AS ReportType,
                ac.ContextState,
                ac.CreatedAt,
                ac.ExpiresAt,
                ac.LastAccessedAt,
                ac.IpAddress,
                SUBSTRING(ac.UserAgent, 1, 100) AS UserAgentPreview
            FROM dbo.AuthenticationContexts ac
            INNER JOIN dbo.PhoneNumbers pn ON ac.MobileNumberId = pn.UniqueId
            WHERE pn.PhoneNumber = @PhoneNumber
                AND (@Region IS NULL OR pn.Region = @Region)
                AND ac.IsActive = 1
                AND ac.IsDeleted = 0;
            
            -- Recent verification flows
            SELECT 
                'Recent Verifications' AS ReportType,
                vf.Status,
                vf.Purpose,
                vf.CreatedAt,
                vf.ExpiresAt,
                vf.OtpCount
            FROM dbo.VerificationFlows vf
            INNER JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
            WHERE pn.PhoneNumber = @PhoneNumber
                AND (@Region IS NULL OR pn.Region = @Region)
                AND vf.CreatedAt >= DATEADD(DAY, -30, GETUTCDATE())
                AND vf.IsDeleted = 0
            ORDER BY vf.CreatedAt DESC;
            
            -- Log performance
            DECLARE @Duration INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
            EXEC dbo.LogPerformanceMetric
                @OperationType = 'USER_SUMMARY',
                @TableName = 'sp_GetUserSummary',
                @Duration = @Duration,
                @RowsAffected = @@ROWCOUNT,
                @AdditionalInfo = CONCAT('Phone: ', @PhoneNumber);
                
        END TRY
        BEGIN CATCH
            EXEC dbo.LogError
                @ProcedureName = 'sp_GetUserSummary',
                @ErrorMessage = ERROR_MESSAGE();
            THROW;
        END CATCH
    END;

    /*
    ================================================================================
    Procedure: sp_CleanupExpiredData
    Purpose: Clean up expired data across various tables for maintenance
    
    Parameters:
    - @DryRun: If 1, show what would be deleted without actually deleting
    - @DaysOld: Number of days old for cleanup (default 30)
    
    Returns: Cleanup summary information
    ================================================================================
    */
    PRINT '🧹 Creating CleanupExpiredData procedure...';
    
        CREATE PROCEDURE dbo.sp_CleanupExpiredData
        @DryRun BIT = 1,
        @DaysOld INT = 30
    AS
    BEGIN
        SET NOCOUNT ON;
        
        BEGIN TRY
            DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
            DECLARE @CutoffDate DATETIME2(7) = DATEADD(DAY, -@DaysOld, GETUTCDATE());
            DECLARE @TotalRowsAffected INT = 0;
            
            -- Expired verification flows
            DECLARE @ExpiredFlows INT;
            SELECT @ExpiredFlows = COUNT(*)
            FROM dbo.VerificationFlows
            WHERE Status = 'expired' 
                AND UpdatedAt < @CutoffDate
                AND IsDeleted = 0;
            
            -- Expired OTP records
            DECLARE @ExpiredOtps INT;
            SELECT @ExpiredOtps = COUNT(*)
            FROM dbo.OtpRecords
            WHERE Status = 'expired' 
                AND UpdatedAt < @CutoffDate
                AND IsDeleted = 0;
                
            -- Expired authentication contexts
            DECLARE @ExpiredContexts INT;
            SELECT @ExpiredContexts = COUNT(*)
            FROM dbo.AuthenticationContexts
            WHERE ContextState = 'expired'
                AND UpdatedAt < @CutoffDate
                AND IsDeleted = 0;
                
            -- Old audit log entries
            DECLARE @OldAuditLogs INT;
            SELECT @OldAuditLogs = COUNT(*)
            FROM dbo.AuditLog
            WHERE CreatedAt < DATEADD(DAY, -90, GETUTCDATE()); -- Keep audit logs longer
            
            -- Display cleanup summary
            SELECT 
                'Cleanup Summary' AS ReportType,
                @DryRun AS IsDryRun,
                @ExpiredFlows AS ExpiredVerificationFlows,
                @ExpiredOtps AS ExpiredOtpRecords,
                @ExpiredContexts AS ExpiredAuthenticationContexts,
                @OldAuditLogs AS OldAuditLogEntries,
                @CutoffDate AS CutoffDate;
            
            -- Perform cleanup if not dry run
            IF @DryRun = 0
            BEGIN
                BEGIN TRANSACTION;
                
                -- Soft delete expired verification flows
                UPDATE dbo.VerificationFlows 
                SET IsDeleted = 1, UpdatedAt = GETUTCDATE()
                WHERE Status = 'expired' 
                    AND UpdatedAt < @CutoffDate
                    AND IsDeleted = 0;
                SET @TotalRowsAffected += @@ROWCOUNT;
                
                -- Soft delete expired OTP records
                UPDATE dbo.OtpRecords 
                SET IsDeleted = 1, UpdatedAt = GETUTCDATE()
                WHERE Status = 'expired' 
                    AND UpdatedAt < @CutoffDate
                    AND IsDeleted = 0;
                SET @TotalRowsAffected += @@ROWCOUNT;
                
                -- Soft delete expired authentication contexts
                UPDATE dbo.AuthenticationContexts 
                SET IsDeleted = 1, UpdatedAt = GETUTCDATE()
                WHERE ContextState = 'expired'
                    AND UpdatedAt < @CutoffDate
                    AND IsDeleted = 0;
                SET @TotalRowsAffected += @@ROWCOUNT;
                
                -- Clean old audit logs (hard delete for space)
                DELETE FROM dbo.AuditLog
                WHERE CreatedAt < DATEADD(DAY, -90, GETUTCDATE());
                SET @TotalRowsAffected += @@ROWCOUNT;
                
                COMMIT TRANSACTION;
                
                -- Log cleanup activity
                EXEC dbo.LogAuditEvent
                    @TableName = 'SYSTEM',
                    @OperationType = 'DATA_CLEANUP',
                    @RecordId = NULL,
                    @OldValues = NULL,
                    @NewValues = CONCAT('Rows affected: ', @TotalRowsAffected),
                    @ApplicationContext = 'sp_CleanupExpiredData',
                    @Success = 1;
            END
            
            -- Log performance
            DECLARE @Duration INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
            EXEC dbo.LogPerformanceMetric
                @OperationType = 'DATA_CLEANUP',
                @TableName = 'sp_CleanupExpiredData',
                @Duration = @Duration,
                @RowsAffected = @TotalRowsAffected,
                @AdditionalInfo = CONCAT('DryRun: ', @DryRun, ', DaysOld: ', @DaysOld);
                
        END TRY
        BEGIN CATCH
            IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
            
            EXEC dbo.LogError
                @ProcedureName = 'sp_CleanupExpiredData',
                @ErrorMessage = ERROR_MESSAGE();
            THROW;
        END CATCH
    END;

    /*
    ================================================================================
    Procedure: sp_GenerateActivityReport
    Purpose: Generate system activity report for specified date range
    
    Parameters:
    - @StartDate: Report start date (default 7 days ago)
    - @EndDate: Report end date (default now)
    
    Returns: Comprehensive activity report
    ================================================================================
    */
    PRINT '📊 Creating GenerateActivityReport procedure...';
    
        CREATE PROCEDURE dbo.sp_GenerateActivityReport
        @StartDate DATETIME2(7) = NULL,
        @EndDate DATETIME2(7) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Set default dates
        IF @StartDate IS NULL SET @StartDate = DATEADD(DAY, -7, GETUTCDATE());
        IF @EndDate IS NULL SET @EndDate = GETUTCDATE();
        
        BEGIN TRY
            DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
            
            -- Report header
            SELECT 
                'System Activity Report' AS ReportType,
                @StartDate AS ReportStartDate,
                @EndDate AS ReportEndDate,
                DATEDIFF(DAY, @StartDate, @EndDate) AS ReportDays,
                GETUTCDATE() AS GeneratedAt;
            
            -- User registration activity
            SELECT 
                'User Registration Activity' AS ReportSection,
                COUNT(*) AS TotalNewMemberships,
                COUNT(CASE WHEN Status = 'active' THEN 1 END) AS ActiveMemberships,
                COUNT(CASE WHEN CreationStatus = 'passphrase_set' THEN 1 END) AS FullyConfiguredMemberships
            FROM dbo.Memberships
            WHERE CreatedAt BETWEEN @StartDate AND @EndDate
                AND IsDeleted = 0;
            
            -- Verification activity
            SELECT 
                'Verification Activity' AS ReportSection,
                COUNT(*) AS TotalVerificationFlows,
                COUNT(CASE WHEN Status = 'verified' THEN 1 END) AS SuccessfulVerifications,
                COUNT(CASE WHEN Status = 'failed' THEN 1 END) AS FailedVerifications,
                COUNT(CASE WHEN Status = 'pending' THEN 1 END) AS PendingVerifications,
                AVG(OtpCount) AS AverageOtpCount
            FROM dbo.VerificationFlows
            WHERE CreatedAt BETWEEN @StartDate AND @EndDate
                AND IsDeleted = 0;
            
            -- Authentication activity
            SELECT 
                'Authentication Activity' AS ReportSection,
                COUNT(*) AS TotalLoginAttempts,
                COUNT(CASE WHEN IsSuccess = 1 THEN 1 END) AS SuccessfulLogins,
                COUNT(CASE WHEN IsSuccess = 0 THEN 1 END) AS FailedLogins,
                CAST(COUNT(CASE WHEN IsSuccess = 1 THEN 1 END) * 100.0 / COUNT(*) AS DECIMAL(5,2)) AS SuccessRate
            FROM dbo.LoginAttempts
            WHERE Timestamp BETWEEN @StartDate AND @EndDate;
            
            -- Error activity
            SELECT 
                'System Health' AS ReportSection,
                COUNT(*) AS TotalErrors,
                COUNT(DISTINCT ProcedureName) AS AffectedProcedures
            FROM dbo.ErrorLog
            WHERE CreatedAt BETWEEN @StartDate AND @EndDate;
            
            -- Top procedures by performance
            SELECT TOP 10
                'Performance Overview' AS ReportSection,
                OperationType,
                TableName,
                COUNT(*) AS ExecutionCount,
                AVG(Duration) AS AvgDurationMs,
                MAX(Duration) AS MaxDurationMs,
                SUM(RowsAffected) AS TotalRowsAffected
            FROM dbo.PerformanceMetrics
            WHERE CreatedAt BETWEEN @StartDate AND @EndDate
            GROUP BY OperationType, TableName
            ORDER BY AVG(Duration) DESC;
            
            -- Log performance
            DECLARE @Duration INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
            EXEC dbo.LogPerformanceMetric
                @OperationType = 'ACTIVITY_REPORT',
                @TableName = 'sp_GenerateActivityReport',
                @Duration = @Duration,
                @RowsAffected = @@ROWCOUNT,
                @AdditionalInfo = CONCAT('Date range: ', @StartDate, ' to ', @EndDate);
                
        END TRY
        BEGIN CATCH
            EXEC dbo.LogError
                @ProcedureName = 'sp_GenerateActivityReport',
                @ErrorMessage = ERROR_MESSAGE();
            THROW;
        END CATCH
    END;

    -- Performance tracking
    DECLARE @Duration INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'HELPER_DEPLOYMENT',
        @TableName = 'BusinessHelpers',
        @Duration = @Duration,
        @RowsAffected = 5,
        @AdditionalInfo = 'Business Helper Functions deployed successfully';

    COMMIT TRANSACTION;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'SUCCESS', 
        EndTime = GETUTCDATE(), 
        Message = 'Business Helper Functions deployed successfully - 2 functions and 3 procedures created',
        RowsAffected = 5
    WHERE Id = @DeploymentId;

    PRINT '✅ Business Helper Functions deployment completed successfully';
    PRINT CONCAT('📊 Deployment completed in ', @Duration, 'ms');
    PRINT '   ✓ fn_GetMembershipStatus - Membership status lookup function';
    PRINT '   ✓ fn_IsPhoneNumberActive - Phone number activity check function';
    PRINT '   ✓ sp_GetUserSummary - Comprehensive user information procedure';
    PRINT '   ✓ sp_CleanupExpiredData - Data maintenance procedure';
    PRINT '   ✓ sp_GenerateActivityReport - Activity reporting procedure';
    
END TRY
BEGIN CATCH
    -- Rollback transaction on error
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    
    SET @ErrorMessage = ERROR_MESSAGE();
    
    -- Log error
    EXEC dbo.LogError
        @ProcedureName = '07_ViewsHelpers/02_BusinessHelpers.sql',
        @ErrorMessage = @ErrorMessage;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'ERROR', 
        EndTime = GETUTCDATE(), 
        Message = CONCAT('Business Helper Functions deployment failed: ', @ErrorMessage)
    WHERE Id = @DeploymentId;
    
    PRINT '❌ Business Helper Functions deployment failed';
    PRINT CONCAT('Error: ', @ErrorMessage);
    
    -- Re-raise error to halt deployment
    THROW;
END CATCH;