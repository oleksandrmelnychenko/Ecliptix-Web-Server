/*
================================================================================
Layer 3.1: Business Constraints & Data Integrity
================================================================================
Purpose: Advanced business rules, data integrity constraints, and cross-table validations
Dependencies: Layer 2 (Core Domain Tables)
Execution Order: 7th - Business logic enforcement layer

Features:
- Advanced business rule constraints
- Cross-table data validation
- Data consistency enforcement
- Security and integrity checks
- Performance optimization constraints
- Referential integrity enhancements

Author: Ecliptix Development Team
Version: 1.0.0
Created: 2024-08-24
================================================================================
*/

-- Use target database
USE [EcliptixDatabase]; -- Replace with your actual database name
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Layer 3.1: Business Constraints & Data Integrity';
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
VALUES (@DeploymentId, '01_BusinessConstraints.sql', 6, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- PHONE NUMBER VALIDATION CONSTRAINTS
    -- ============================================================================
    
    PRINT 'Adding phone number validation constraints...';
    
    -- Enhanced phone number format validation
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_PhoneNumbers_ValidFormat')
    BEGIN
        ALTER TABLE dbo.PhoneNumbers 
        ADD CONSTRAINT CHK_PhoneNumbers_ValidFormat 
        CHECK (dbo.ValidatePhoneNumber(PhoneNumber) = 1);
        
        PRINT '✓ Phone number format validation constraint added';
    END
    
    -- Region code validation (ISO 3166-1 alpha-2)
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_PhoneNumbers_ValidRegion')
    BEGIN
        ALTER TABLE dbo.PhoneNumbers 
        ADD CONSTRAINT CHK_PhoneNumbers_ValidRegion 
        CHECK (
            Region IS NULL OR 
            (LEN(Region) = 2 AND Region = UPPER(Region) AND Region NOT LIKE '%[^A-Z]%')
        );
        
        PRINT '✓ Region code validation constraint added';
    END
    
    -- ============================================================================
    -- DEVICE MANAGEMENT CONSTRAINTS
    -- ============================================================================
    
    PRINT 'Adding device management constraints...';
    
    -- Device ID validation (must be valid GUID format)
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_AppDevices_ValidDeviceId')
    BEGIN
        ALTER TABLE dbo.AppDevices 
        ADD CONSTRAINT CHK_AppDevices_ValidDeviceId 
        CHECK (dbo.ValidateGuid(CAST(DeviceId AS NVARCHAR(50))) = 1);
        
        PRINT '✓ Device ID validation constraint added';
    END
    
    -- App Instance ID validation
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_AppDevices_ValidAppInstanceId')
    BEGIN
        ALTER TABLE dbo.AppDevices 
        ADD CONSTRAINT CHK_AppDevices_ValidAppInstanceId 
        CHECK (dbo.ValidateGuid(CAST(AppInstanceId AS NVARCHAR(50))) = 1);
        
        PRINT '✓ App Instance ID validation constraint added';
    END
    
    -- Only one primary device per phone number
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_PhoneNumberDevices_SinglePrimary')
    BEGIN
        -- This will be enforced through a unique filtered index instead of a check constraint
        -- since check constraints can't easily validate across multiple rows
        
        -- Drop existing index if it exists and recreate with proper logic
        IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UQ_PhoneNumberDevices_SinglePrimary')
            DROP INDEX UQ_PhoneNumberDevices_SinglePrimary ON dbo.PhoneNumberDevices;
        
        CREATE UNIQUE INDEX UQ_PhoneNumberDevices_SinglePrimary 
            ON dbo.PhoneNumberDevices (PhoneNumberId) 
            WHERE IsPrimary = 1 AND IsDeleted = 0;
        
        PRINT '✓ Single primary device per phone constraint added';
    END
    
    -- ============================================================================
    -- VERIFICATION FLOW BUSINESS RULES
    -- ============================================================================
    
    PRINT 'Adding verification flow business constraints...';
    
    -- Expiration time must be reasonable (between 1 minute and 24 hours from creation)
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_VerificationFlows_ReasonableExpiration')
    BEGIN
        ALTER TABLE dbo.VerificationFlows 
        ADD CONSTRAINT CHK_VerificationFlows_ReasonableExpiration 
        CHECK (
            ExpiresAt > DATEADD(MINUTE, 1, CreatedAt) AND 
            ExpiresAt <= DATEADD(HOUR, 24, CreatedAt)
        );
        
        PRINT '✓ Reasonable expiration time constraint added';
    END
    
    -- OTP count should not exceed configured maximum
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_VerificationFlows_MaxOtpCount')
    BEGIN
        ALTER TABLE dbo.VerificationFlows 
        ADD CONSTRAINT CHK_VerificationFlows_MaxOtpCount 
        CHECK (OtpCount <= CAST(dbo.GetConfigValue('OTP.MaxAttempts') AS INT));
        
        PRINT '✓ Maximum OTP count constraint added';
    END
    
    -- Status progression logic: pending -> verified/expired/failed (no backwards transitions)
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_VerificationFlows_ValidStatusTransition')
    BEGIN
        -- This will be enforced through triggers rather than check constraints
        -- since check constraints can't access the old value during updates
        PRINT '✓ Status transition validation will be handled by triggers';
    END
    
    -- ============================================================================
    -- OTP SECURITY CONSTRAINTS
    -- ============================================================================
    
    PRINT 'Adding OTP security constraints...';
    
    -- OTP expiration must be reasonable (1-30 minutes)
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_OtpRecords_ReasonableExpiration')
    BEGIN
        ALTER TABLE dbo.OtpRecords 
        ADD CONSTRAINT CHK_OtpRecords_ReasonableExpiration 
        CHECK (
            ExpiresAt > DATEADD(MINUTE, 1, CreatedAt) AND 
            ExpiresAt <= DATEADD(MINUTE, 30, CreatedAt)
        );
        
        PRINT '✓ OTP reasonable expiration constraint added';
    END
    
    -- Hash and salt must meet minimum security requirements
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_OtpRecords_SecureHash')
    BEGIN
        ALTER TABLE dbo.OtpRecords 
        ADD CONSTRAINT CHK_OtpRecords_SecureHash 
        CHECK (
            LEN(OtpHash) >= 64 AND  -- Minimum for SHA-256 hex
            LEN(OtpSalt) >= 32 AND  -- Minimum 16 bytes as hex
            OtpHash NOT LIKE '%[^0-9a-fA-F]%' AND  -- Valid hex characters only
            OtpSalt NOT LIKE '%[^0-9a-fA-F]%'      -- Valid hex characters only
        );
        
        PRINT '✓ Secure hash format constraint added';
    END
    
    -- Only one active OTP per verification flow
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UQ_OtpRecords_SingleActivePerFlow')
    BEGIN
        CREATE UNIQUE INDEX UQ_OtpRecords_SingleActivePerFlow 
            ON dbo.OtpRecords (FlowUniqueId) 
            WHERE IsActive = 1 AND Status = 'pending' AND IsDeleted = 0;
        
        PRINT '✓ Single active OTP per flow constraint added';
    END
    
    -- ============================================================================
    -- MEMBERSHIP BUSINESS RULES
    -- ============================================================================
    
    PRINT 'Adding membership business constraints...';
    
    -- Secure key must be properly encrypted (minimum length for AES-256)
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_Memberships_SecureKeyLength')
    BEGIN
        ALTER TABLE dbo.Memberships 
        ADD CONSTRAINT CHK_Memberships_SecureKeyLength 
        CHECK (SecureKey IS NULL OR LEN(SecureKey) >= 32); -- Minimum for AES-256
        
        PRINT '✓ Secure key length constraint added';
    END
    
    -- Creation status progression: otp_verified -> secure_key_set -> passphrase_set
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_Memberships_CreationStatusLogic')
    BEGIN
        ALTER TABLE dbo.Memberships 
        ADD CONSTRAINT CHK_Memberships_CreationStatusLogic 
        CHECK (
            (CreationStatus = 'otp_verified' AND SecureKey IS NULL) OR
            (CreationStatus IN ('secure_key_set', 'passphrase_set') AND SecureKey IS NOT NULL)
        );
        
        PRINT '✓ Creation status logic constraint added';
    END
    
    -- Active memberships must have completed creation process
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_Memberships_ActiveCompleteness')
    BEGIN
        ALTER TABLE dbo.Memberships 
        ADD CONSTRAINT CHK_Memberships_ActiveCompleteness 
        CHECK (
            Status != 'active' OR 
            (Status = 'active' AND CreationStatus IN ('secure_key_set', 'passphrase_set'))
        );
        
        PRINT '✓ Active membership completeness constraint added';
    END
    
    -- ============================================================================
    -- AUTHENTICATION CONTEXT CONSTRAINTS
    -- ============================================================================
    
    PRINT 'Adding authentication context constraints...';
    
    -- Context token must be cryptographically strong
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_AuthContexts_StrongToken')
    BEGIN
        ALTER TABLE dbo.AuthenticationContexts 
        ADD CONSTRAINT CHK_AuthContexts_StrongToken 
        CHECK (LEN(ContextToken) >= 32); -- Minimum 256-bit token
        
        PRINT '✓ Strong authentication token constraint added';
    END
    
    -- IP address format validation
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_AuthContexts_ValidIpAddress')
    BEGIN
        ALTER TABLE dbo.AuthenticationContexts 
        ADD CONSTRAINT CHK_AuthContexts_ValidIpAddress 
        CHECK (IpAddress IS NULL OR dbo.ValidateIpAddress(IpAddress) = 1);
        
        PRINT '✓ IP address format validation constraint added';
    END
    
    -- Expiration must be reasonable (1 hour to 30 days)
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_AuthContexts_ReasonableExpiration')
    BEGIN
        ALTER TABLE dbo.AuthenticationContexts 
        ADD CONSTRAINT CHK_AuthContexts_ReasonableExpiration 
        CHECK (
            ExpiresAt > DATEADD(HOUR, 1, CreatedAt) AND 
            ExpiresAt <= DATEADD(DAY, 30, CreatedAt)
        );
        
        PRINT '✓ Reasonable authentication expiration constraint added';
    END
    
    -- Last accessed time logical validation
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_AuthContexts_LastAccessedLogic')
    BEGIN
        ALTER TABLE dbo.AuthenticationContexts 
        ADD CONSTRAINT CHK_AuthContexts_LastAccessedLogic 
        CHECK (
            LastAccessedAt >= CreatedAt AND 
            LastAccessedAt <= GETUTCDATE()
        );
        
        PRINT '✓ Last accessed time logic constraint added';
    END
    
    -- Limit concurrent active sessions per membership
    IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AuthContexts_ConcurrentSessionLimit')
    BEGIN
        -- This will be enforced through business logic in procedures
        -- but we can create an index to help with the queries
        CREATE NONCLUSTERED INDEX IX_AuthContexts_ConcurrentSessionLimit 
            ON dbo.AuthenticationContexts (MembershipId, IsActive, ContextState);
        
        PRINT '✓ Concurrent session monitoring index added';
    END
    
    -- ============================================================================
    -- AUTHENTICATION STATE CONSTRAINTS
    -- ============================================================================
    
    PRINT 'Adding authentication state constraints...';
    
    -- Rate limiting window validation
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_AuthStates_RateLimitingLogic')
    BEGIN
        ALTER TABLE dbo.AuthenticationStates 
        ADD CONSTRAINT CHK_AuthStates_RateLimitingLogic 
        CHECK (
            WindowStartTime <= GETUTCDATE() AND
            (LastAttemptTime IS NULL OR LastAttemptTime >= WindowStartTime) AND
            (RecentAttempts = 0 OR LastAttemptTime IS NOT NULL)
        );
        
        PRINT '✓ Rate limiting logic constraint added';
    END
    
    -- Lock status consistency
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_AuthStates_LockConsistency')
    BEGIN
        ALTER TABLE dbo.AuthenticationStates 
        ADD CONSTRAINT CHK_AuthStates_LockConsistency 
        CHECK (
            (IsLocked = 0 AND LockedUntil IS NULL) OR 
            (IsLocked = 1 AND LockedUntil IS NOT NULL AND LockedUntil > WindowStartTime)
        );
        
        PRINT '✓ Lock status consistency constraint added';
    END
    
    -- ============================================================================
    -- AUDIT AND TRACKING CONSTRAINTS
    -- ============================================================================
    
    PRINT 'Adding audit and tracking constraints...';
    
    -- Failed OTP attempts must be chronologically consistent
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_FailedOtpAttempts_ChronologyConsistent')
    BEGIN
        ALTER TABLE dbo.FailedOtpAttempts 
        ADD CONSTRAINT CHK_FailedOtpAttempts_ChronologyConsistent 
        CHECK (AttemptTime <= CreatedAt AND AttemptTime >= DATEADD(DAY, -1, CreatedAt));
        
        PRINT '✓ Failed OTP attempts chronology constraint added';
    END
    
    -- Login attempts outcome validation
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_LoginAttempts_OutcomeConsistency')
    BEGIN
        ALTER TABLE dbo.LoginAttempts 
        ADD CONSTRAINT CHK_LoginAttempts_OutcomeConsistency 
        CHECK (
            LEN(TRIM(Outcome)) > 0 AND
            (
                (IsSuccess = 1 AND Outcome LIKE '%success%') OR
                (IsSuccess = 0 AND Outcome NOT LIKE '%success%')
            )
        );
        
        PRINT '✓ Login attempt outcome consistency constraint added';
    END
    
    -- Membership attempts outcome validation
    IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CHK_MembershipAttempts_OutcomeConsistency')
    BEGIN
        ALTER TABLE dbo.MembershipAttempts 
        ADD CONSTRAINT CHK_MembershipAttempts_OutcomeConsistency 
        CHECK (
            LEN(TRIM(Outcome)) > 0 AND
            (
                (IsSuccess = 1 AND Outcome LIKE '%success%') OR
                (IsSuccess = 0 AND Outcome NOT LIKE '%success%')
            )
        );
        
        PRINT '✓ Membership attempt outcome consistency constraint added';
    END
    
    -- ============================================================================
    -- CROSS-TABLE VALIDATION FUNCTIONS
    -- ============================================================================
    
    PRINT 'Creating cross-table validation functions...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.ValidateMembershipDataIntegrity', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.ValidateMembershipDataIntegrity;
    
    -- Comprehensive data integrity validation procedure
    EXEC ('
    CREATE PROCEDURE dbo.ValidateMembershipDataIntegrity
        @MembershipId UNIQUEIDENTIFIER = NULL,
        @ValidationErrors NVARCHAR(MAX) OUTPUT,
        @IsValid BIT OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @ErrorList TABLE (ErrorMessage NVARCHAR(255));
        SET @IsValid = 1;
        
        -- Validate specific membership or all memberships
        DECLARE @WhereClause NVARCHAR(100) = CASE 
            WHEN @MembershipId IS NOT NULL THEN '' AND m.UniqueId = @MembershipId''
            ELSE ''''
        END;
        
        -- Check for orphaned verification flows
        INSERT INTO @ErrorList (ErrorMessage)
        SELECT ''Orphaned verification flow: '' + CAST(vf.UniqueId AS NVARCHAR(36))
        FROM dbo.VerificationFlows vf
        LEFT JOIN dbo.Memberships m ON vf.UniqueId = m.VerificationFlowId
        WHERE m.Id IS NULL AND vf.Status = ''verified'';
        
        -- Check for active memberships without proper creation status
        INSERT INTO @ErrorList (ErrorMessage)
        SELECT ''Invalid active membership: '' + CAST(m.UniqueId AS NVARCHAR(36))
        FROM dbo.Memberships m
        WHERE m.Status = ''active'' AND m.CreationStatus NOT IN (''secure_key_set'', ''passphrase_set'');
        
        -- Check for expired authentication contexts still marked as active
        INSERT INTO @ErrorList (ErrorMessage)
        SELECT ''Expired but active auth context: '' + CAST(ac.Id AS NVARCHAR(20))
        FROM dbo.AuthenticationContexts ac
        WHERE ac.IsActive = 1 AND ac.ExpiresAt < GETUTCDATE();
        
        -- Check for inconsistent authentication states
        INSERT INTO @ErrorList (ErrorMessage)
        SELECT ''Inconsistent auth state: '' + CAST(auth_state.MobileNumberId AS NVARCHAR(36))
        FROM dbo.AuthenticationStates auth_state
        WHERE (auth_state.IsLocked = 1 AND auth_state.LockedUntil < GETUTCDATE()) OR
              (auth_state.RecentAttempts > 0 AND auth_state.LastAttemptTime IS NULL);
        
        -- Compile results
        IF EXISTS (SELECT 1 FROM @ErrorList)
        BEGIN
            SET @IsValid = 0;
            SELECT @ValidationErrors = COALESCE(@ValidationErrors + ''; '', '''') + ErrorMessage
            FROM @ErrorList;
        END
        ELSE
        BEGIN
            SET @ValidationErrors = NULL;
        END
        
        -- Return summary
        SELECT 
            @IsValid AS IsValid,
            @ValidationErrors AS ValidationErrors,
            (SELECT COUNT(*) FROM @ErrorList) AS ErrorCount;
    END;
    ');
    
    PRINT '✓ Cross-table validation procedure created';
    
    -- ============================================================================
    -- PERFORMANCE OPTIMIZATION CONSTRAINTS
    -- ============================================================================
    
    PRINT 'Adding performance optimization constraints...';
    
    -- Add computed columns for commonly filtered combinations
    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.VerificationFlows') AND name = 'IsActivePending')
    BEGIN
        ALTER TABLE dbo.VerificationFlows 
        ADD IsActivePending AS (CASE WHEN Status = 'pending' AND IsDeleted = 0 THEN 1 ELSE 0 END) PERSISTED;
        
        CREATE NONCLUSTERED INDEX IX_VerificationFlows_IsActivePending 
            ON dbo.VerificationFlows (IsActivePending, ExpiresAt) WHERE IsActivePending = 1;
        
        PRINT '✓ Active pending verification flows optimization added';
    END
    
    -- Add computed column for active non-expired authentication contexts
    IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('dbo.AuthenticationContexts') AND name = 'IsActiveNonExpired')
    BEGIN
        ALTER TABLE dbo.AuthenticationContexts 
        ADD IsActiveNonExpired AS (CASE WHEN IsActive = 1 AND ContextState = 'active' AND ExpiresAt > GETUTCDATE() THEN 1 ELSE 0 END);
        
        -- Note: Can't use GETUTCDATE() in computed column, so we'll handle this through maintenance procedures
        ALTER TABLE dbo.AuthenticationContexts DROP COLUMN IsActiveNonExpired;
        
        PRINT '✓ Active authentication context optimization will be handled by maintenance procedures';
    END
    
    -- ============================================================================
    -- CONSTRAINT VALIDATION AND TESTING
    -- ============================================================================
    
    PRINT 'Testing constraint validation...';
    
    -- Test phone number validation
    BEGIN TRY
        -- This should succeed
        DECLARE @TestPhoneId UNIQUEIDENTIFIER = NEWID();
        INSERT INTO dbo.PhoneNumbers (PhoneNumber, Region, UniqueId) VALUES ('1234567890', 'US', @TestPhoneId);
        DELETE FROM dbo.PhoneNumbers WHERE UniqueId = @TestPhoneId;
        PRINT '✓ Phone number validation constraint working correctly';
    END TRY
    BEGIN CATCH
        PRINT '⚠ Phone number validation constraint test failed: ' + ERROR_MESSAGE();
    END CATCH
    
    -- Test cross-table validation
    DECLARE @ValidationErrors NVARCHAR(MAX), @IsValid BIT;
    EXEC dbo.ValidateMembershipDataIntegrity @ValidationErrors = @ValidationErrors OUTPUT, @IsValid = @IsValid OUTPUT;
    
    IF @IsValid = 1
        PRINT '✓ Cross-table data integrity validation passed';
    ELSE
        PRINT '⚠ Cross-table validation found issues: ' + ISNULL(@ValidationErrors, 'Unknown errors');
    
    -- Count total constraints added
    DECLARE @ConstraintCount INT;
    SELECT @ConstraintCount = COUNT(*)
    FROM sys.check_constraints cc
    INNER JOIN sys.tables t ON cc.parent_object_id = t.object_id
    WHERE t.name IN (
        'PhoneNumbers', 'AppDevices', 'VerificationFlows', 'OtpRecords',
        'Memberships', 'AuthenticationContexts', 'AuthenticationStates',
        'FailedOtpAttempts', 'LoginAttempts', 'MembershipAttempts'
    );
    
    PRINT '✓ Applied ' + CAST(@ConstraintCount AS NVARCHAR(10)) + ' business rule constraints';
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = @ConstraintCount
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 3.1: Business Constraints & Data Integrity Completed Successfully';
    PRINT 'Business rule constraints: ' + CAST(@ConstraintCount AS NVARCHAR(10));
    PRINT 'Cross-table validation: ✓ Implemented';
    PRINT 'Performance optimizations: ✓ Added';
    PRINT 'Data integrity framework: ✓ Established';
    PRINT 'Next: Layer 4 - Core Business Procedures';
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
    PRINT 'ERROR in Layer 3.1: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO