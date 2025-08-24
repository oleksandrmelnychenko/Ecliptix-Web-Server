/*
================================================================================
Layer 7.1: Business Views
================================================================================
Purpose: Create business-focused views for common queries, reporting, and 
         monitoring across the Ecliptix system

Dependencies: 
- Layer 1: Configuration & Core Infrastructure (all files)
- Layer 2: Core Domain Tables (01_CoreDomainTables.sql)
- Layer 6: Triggers (all files)

Version: 1.0.0
Author: Ecliptix Development Team
Created: 2024-08-24

Features:
- ActiveMemberships view for user management queries
- VerificationFlowStatus view for verification monitoring
- AuthenticationSummary view for authentication analytics
- SystemHealthDashboard view for operational monitoring
- Performance optimized with appropriate indexes

Views Created:
- vw_ActiveMemberships (active user memberships with phone details)
- vw_VerificationFlowStatus (verification flow progress tracking)
- vw_AuthenticationSummary (authentication session overview)
- vw_SystemHealthDashboard (system operational health)
================================================================================
*/

-- Log deployment start
INSERT INTO dbo.DeploymentLog (ScriptName, Status, StartTime, Message)
VALUES ('07_ViewsHelpers/01_BusinessViews.sql', 'RUNNING', GETUTCDATE(), 'Starting Business Views deployment');

DECLARE @DeploymentId BIGINT = SCOPE_IDENTITY();
DECLARE @ErrorMessage NVARCHAR(4000);
DECLARE @StartTime DATETIME2(7) = GETUTCDATE();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- Performance tracking
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'VIEW_DEPLOYMENT',
        @TableName = 'BusinessViews',
        @Duration = 0,
        @RowsAffected = 0,
        @AdditionalInfo = 'Starting Business Views deployment';

    PRINT '🚀 Deploying Business Views...';

    -- Drop existing views if they exist
    IF OBJECT_ID('dbo.vw_ActiveMemberships', 'V') IS NOT NULL 
        DROP VIEW dbo.vw_ActiveMemberships;
    
    IF OBJECT_ID('dbo.vw_VerificationFlowStatus', 'V') IS NOT NULL 
        DROP VIEW dbo.vw_VerificationFlowStatus;
        
    IF OBJECT_ID('dbo.vw_AuthenticationSummary', 'V') IS NOT NULL 
        DROP VIEW dbo.vw_AuthenticationSummary;
        
    IF OBJECT_ID('dbo.vw_SystemHealthDashboard', 'V') IS NOT NULL 
        DROP VIEW dbo.vw_SystemHealthDashboard;

    /*
    ================================================================================
    View: vw_ActiveMemberships
    Purpose: Consolidated view of active user memberships with phone number details
    
    Business Use Cases:
    - User management and lookup
    - Active user reporting
    - Phone number association tracking
    ================================================================================
    */
    PRINT '👤 Creating ActiveMemberships view...';
    
    EXEC('
    CREATE VIEW dbo.vw_ActiveMemberships AS
    SELECT 
        m.UniqueId AS MembershipId,
        m.Id AS MembershipInternalId,
        pn.PhoneNumber,
        pn.Region AS PhoneRegion,
        pn.UniqueId AS PhoneNumberId,
        ad.DeviceId,
        ad.DeviceType,
        ad.AppInstanceId,
        m.Status AS MembershipStatus,
        m.CreationStatus,
        m.CreatedAt AS MembershipCreatedAt,
        m.UpdatedAt AS MembershipUpdatedAt,
        pn.CreatedAt AS PhoneCreatedAt,
        ad.CreatedAt AS DeviceCreatedAt,
        CASE 
            WHEN m.Status = ''active'' AND m.CreationStatus = ''passphrase_set'' THEN ''Fully Active''
            WHEN m.Status = ''active'' AND m.CreationStatus = ''secure_key_set'' THEN ''Active - Key Set''
            WHEN m.Status = ''active'' AND m.CreationStatus = ''otp_verified'' THEN ''Active - OTP Only''
            WHEN m.Status = ''inactive'' THEN ''Inactive''
            ELSE ''Unknown''
        END AS MembershipDisplayStatus
    FROM dbo.Memberships m
    INNER JOIN dbo.PhoneNumbers pn ON m.PhoneNumberId = pn.UniqueId
    INNER JOIN dbo.AppDevices ad ON m.AppDeviceId = ad.UniqueId
    WHERE m.IsDeleted = 0
        AND pn.IsDeleted = 0
        AND ad.IsDeleted = 0;
    ');

    /*
    ================================================================================
    View: vw_VerificationFlowStatus
    Purpose: Comprehensive view of verification flow status with related OTP information
    
    Business Use Cases:
    - Verification process monitoring
    - OTP status tracking
    - Failed attempt analysis
    ================================================================================
    */
    PRINT '🔄 Creating VerificationFlowStatus view...';
    
    EXEC('
    CREATE VIEW dbo.vw_VerificationFlowStatus AS
    SELECT 
        vf.UniqueId AS FlowId,
        vf.Id AS FlowInternalId,
        pn.PhoneNumber,
        pn.Region AS PhoneRegion,
        ad.DeviceId,
        vf.Status AS FlowStatus,
        vf.Purpose AS FlowPurpose,
        vf.ExpiresAt AS FlowExpiresAt,
        vf.OtpCount,
        vf.CreatedAt AS FlowCreatedAt,
        vf.UpdatedAt AS FlowUpdatedAt,
        
        -- Current active OTP information
        otp.UniqueId AS CurrentOtpId,
        otp.Status AS OtpStatus,
        otp.ExpiresAt AS OtpExpiresAt,
        otp.IsActive AS OtpIsActive,
        otp.CreatedAt AS OtpCreatedAt,
        
        -- Failed attempt counts
        ISNULL(failed_counts.FailedAttempts, 0) AS TotalFailedAttempts,
        
        -- Status indicators
        CASE 
            WHEN vf.ExpiresAt < GETUTCDATE() THEN ''Expired''
            WHEN vf.Status = ''verified'' THEN ''Successfully Verified''
            WHEN vf.Status = ''failed'' THEN ''Failed''
            WHEN vf.Status = ''pending'' AND otp.Status = ''pending'' THEN ''Awaiting OTP Verification''
            WHEN vf.Status = ''pending'' AND otp.Status IS NULL THEN ''No OTP Generated''
            ELSE ''Unknown Status''
        END AS StatusDescription,
        
        CASE 
            WHEN vf.ExpiresAt < GETUTCDATE() THEN 1
            WHEN otp.ExpiresAt < GETUTCDATE() THEN 1
            ELSE 0
        END AS IsExpired
        
    FROM dbo.VerificationFlows vf
    INNER JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
    INNER JOIN dbo.AppDevices ad ON vf.AppDeviceId = ad.UniqueId
    LEFT JOIN dbo.OtpRecords otp ON vf.UniqueId = otp.FlowUniqueId 
        AND otp.IsActive = 1 
        AND otp.IsDeleted = 0
    LEFT JOIN (
        SELECT 
            foa.FlowUniqueId,
            COUNT(*) AS FailedAttempts
        FROM dbo.FailedOtpAttempts foa
        WHERE foa.IsDeleted = 0
        GROUP BY foa.FlowUniqueId
    ) failed_counts ON vf.UniqueId = failed_counts.FlowUniqueId
    WHERE vf.IsDeleted = 0
        AND pn.IsDeleted = 0
        AND ad.IsDeleted = 0;
    ');

    /*
    ================================================================================
    View: vw_AuthenticationSummary
    Purpose: Authentication session and context overview for monitoring and analytics
    
    Business Use Cases:
    - Session management
    - Authentication monitoring
    - Security analysis
    ================================================================================
    */
    PRINT '🔐 Creating AuthenticationSummary view...';
    
    EXEC('
    CREATE VIEW dbo.vw_AuthenticationSummary AS
    SELECT 
        ac.Id AS ContextId,
        ac.ContextToken,
        m.UniqueId AS MembershipId,
        pn.PhoneNumber,
        pn.Region AS PhoneRegion,
        ac.CreatedAt AS ContextCreatedAt,
        ac.ExpiresAt AS ContextExpiresAt,
        ac.LastAccessedAt,
        ac.IsActive AS ContextIsActive,
        ac.ContextState,
        ac.IpAddress,
        ac.UserAgent,
        
        -- Authentication state information
        ast.IsLocked AS AccountIsLocked,
        ast.LockedUntil AS AccountLockedUntil,
        ast.RecentAttempts,
        ast.LastAttemptTime,
        
        -- Status indicators
        CASE 
            WHEN ac.ExpiresAt < GETUTCDATE() THEN ''Expired''
            WHEN ac.ContextState = ''expired'' THEN ''Expired''
            WHEN ac.ContextState = ''invalidated'' THEN ''Invalidated''
            WHEN ac.IsActive = 1 AND ac.ContextState = ''active'' THEN ''Active''
            ELSE ''Inactive''
        END AS ContextStatusDescription,
        
        CASE 
            WHEN ast.IsLocked = 1 AND ast.LockedUntil > GETUTCDATE() THEN ''Account Locked''
            WHEN ast.IsLocked = 1 THEN ''Account Previously Locked''
            WHEN ast.RecentAttempts > 3 THEN ''Multiple Recent Attempts''
            ELSE ''Normal''
        END AS SecurityStatusDescription,
        
        -- Time calculations
        DATEDIFF(MINUTE, ac.CreatedAt, GETUTCDATE()) AS SessionAgeMinutes,
        DATEDIFF(MINUTE, ac.LastAccessedAt, GETUTCDATE()) AS MinutesSinceLastAccess,
        CASE 
            WHEN ac.ExpiresAt > GETUTCDATE() THEN DATEDIFF(MINUTE, GETUTCDATE(), ac.ExpiresAt)
            ELSE 0
        END AS MinutesUntilExpiry
        
    FROM dbo.AuthenticationContexts ac
    INNER JOIN dbo.Memberships m ON ac.MembershipId = m.UniqueId
    INNER JOIN dbo.PhoneNumbers pn ON ac.MobileNumberId = pn.UniqueId
    LEFT JOIN dbo.AuthenticationStates ast ON ac.MobileNumberId = ast.MobileNumberId
    WHERE ac.IsDeleted = 0
        AND m.IsDeleted = 0
        AND pn.IsDeleted = 0;
    ');

    /*
    ================================================================================
    View: vw_SystemHealthDashboard
    Purpose: System operational health and performance metrics overview
    
    Business Use Cases:
    - Operations dashboard
    - System monitoring
    - Performance tracking
    ================================================================================
    */
    PRINT '📊 Creating SystemHealthDashboard view...';
    
    EXEC('
    CREATE VIEW dbo.vw_SystemHealthDashboard AS
    SELECT 
        -- Current timestamp for dashboard refresh
        GETUTCDATE() AS RefreshTime,
        
        -- Active entities count
        (SELECT COUNT(*) FROM dbo.Memberships WHERE IsDeleted = 0 AND Status = ''active'') AS ActiveMemberships,
        (SELECT COUNT(*) FROM dbo.VerificationFlows WHERE IsDeleted = 0 AND Status = ''pending'') AS PendingVerifications,
        (SELECT COUNT(*) FROM dbo.AuthenticationContexts WHERE IsDeleted = 0 AND IsActive = 1 AND ContextState = ''active'') AS ActiveSessions,
        (SELECT COUNT(*) FROM dbo.OtpRecords WHERE IsDeleted = 0 AND IsActive = 1 AND Status = ''pending'') AS PendingOtps,
        
        -- Today''s activity counts
        (SELECT COUNT(*) FROM dbo.Memberships WHERE CreatedAt >= CAST(GETUTCDATE() AS DATE)) AS TodayNewMemberships,
        (SELECT COUNT(*) FROM dbo.VerificationFlows WHERE CreatedAt >= CAST(GETUTCDATE() AS DATE)) AS TodayVerificationFlows,
        (SELECT COUNT(*) FROM dbo.LoginAttempts WHERE Timestamp >= CAST(GETUTCDATE() AS DATE)) AS TodayLoginAttempts,
        (SELECT COUNT(*) FROM dbo.LoginAttempts WHERE Timestamp >= CAST(GETUTCDATE() AS DATE) AND IsSuccess = 1) AS TodaySuccessfulLogins,
        
        -- System health indicators
        (SELECT COUNT(*) FROM dbo.AuthenticationStates WHERE IsLocked = 1 AND LockedUntil > GETUTCDATE()) AS CurrentlyLockedAccounts,
        (SELECT COUNT(*) FROM dbo.VerificationFlows WHERE Status = ''pending'' AND ExpiresAt < GETUTCDATE()) AS ExpiredPendingFlows,
        (SELECT COUNT(*) FROM dbo.OtpRecords WHERE Status = ''pending'' AND ExpiresAt < GETUTCDATE()) AS ExpiredPendingOtps,
        (SELECT COUNT(*) FROM dbo.AuthenticationContexts WHERE IsActive = 1 AND ExpiresAt < GETUTCDATE()) AS ExpiredActiveSessions,
        
        -- Error and audit activity (last 24 hours)
        (SELECT COUNT(*) FROM dbo.ErrorLog WHERE CreatedAt >= DATEADD(HOUR, -24, GETUTCDATE())) AS ErrorsLast24Hours,
        (SELECT COUNT(*) FROM dbo.AuditLog WHERE CreatedAt >= DATEADD(HOUR, -24, GETUTCDATE())) AS AuditEventsLast24Hours,
        
        -- Performance indicators
        (SELECT AVG(Duration) FROM dbo.PerformanceMetrics WHERE CreatedAt >= DATEADD(HOUR, -1, GETUTCDATE())) AS AvgOperationDurationLastHour,
        (SELECT COUNT(*) FROM dbo.PerformanceMetrics WHERE Duration > 5000 AND CreatedAt >= DATEADD(HOUR, -1, GETUTCDATE())) AS SlowOperationsLastHour,
        
        -- Circuit breaker status
        (SELECT COUNT(*) FROM dbo.CircuitBreakerStates WHERE State = ''OPEN'') AS OpenCircuitBreakers,
        (SELECT COUNT(*) FROM dbo.CircuitBreakerStates WHERE State = ''HALF_OPEN'') AS HalfOpenCircuitBreakers;
    ');

    -- Performance tracking
    DECLARE @Duration INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'VIEW_DEPLOYMENT',
        @TableName = 'BusinessViews',
        @Duration = @Duration,
        @RowsAffected = 4,
        @AdditionalInfo = 'Business Views deployed successfully';

    COMMIT TRANSACTION;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'SUCCESS', 
        EndTime = GETUTCDATE(), 
        Message = 'Business Views deployed successfully - 4 views created',
        RowsAffected = 4
    WHERE Id = @DeploymentId;

    PRINT '✅ Business Views deployment completed successfully';
    PRINT CONCAT('📊 Deployment completed in ', @Duration, 'ms');
    PRINT '   ✓ vw_ActiveMemberships - User management and lookup';
    PRINT '   ✓ vw_VerificationFlowStatus - Verification process monitoring';
    PRINT '   ✓ vw_AuthenticationSummary - Authentication session overview';
    PRINT '   ✓ vw_SystemHealthDashboard - System operational health monitoring';
    
END TRY
BEGIN CATCH
    -- Rollback transaction on error
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    
    SET @ErrorMessage = ERROR_MESSAGE();
    
    -- Log error
    EXEC dbo.LogError
        @ProcedureName = '07_ViewsHelpers/01_BusinessViews.sql',
        @ErrorMessage = @ErrorMessage;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'ERROR', 
        EndTime = GETUTCDATE(), 
        Message = CONCAT('Business Views deployment failed: ', @ErrorMessage)
    WHERE Id = @DeploymentId;
    
    PRINT '❌ Business Views deployment failed';
    PRINT CONCAT('Error: ', @ErrorMessage);
    
    -- Re-raise error to halt deployment
    THROW;
END CATCH;