/*
================================================================================
Layer 4.2: Membership Procedures
================================================================================
Purpose: Core membership management procedures with advanced security and monitoring
Dependencies: Layers 1-3 (Infrastructure, Domain Tables, Constraints), Layer 4.1 (Authentication)
Execution Order: 9th - Membership business logic layer

Features:
- Membership creation and management
- Advanced rate limiting and lockout mechanisms  
- Suspicious activity detection and analysis
- Secure key management
- Enhanced login with behavioral analysis
- Complete audit trail for compliance

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
PRINT 'Layer 4.2: Membership Procedures';
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
VALUES (@DeploymentId, '02_MembershipProcedures.sql', 8, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- CLEANUP EXISTING PROCEDURES
    -- ============================================================================
    
    PRINT 'Cleaning up existing membership procedures...';
    
    IF OBJECT_ID('dbo.CreateMembership', 'P') IS NOT NULL DROP PROCEDURE dbo.CreateMembership;
    IF OBJECT_ID('dbo.UpdateMembershipSecureKey', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateMembershipSecureKey;
    IF OBJECT_ID('dbo.LoginMembership', 'P') IS NOT NULL DROP PROCEDURE dbo.LoginMembership;
    IF OBJECT_ID('dbo.LogLoginAttempt', 'P') IS NOT NULL DROP PROCEDURE dbo.LogLoginAttempt;
    IF OBJECT_ID('dbo.LogMembershipAttempt', 'P') IS NOT NULL DROP PROCEDURE dbo.LogMembershipAttempt;
    IF OBJECT_ID('dbo.ValidateMembershipEligibility', 'P') IS NOT NULL DROP PROCEDURE dbo.ValidateMembershipEligibility;
    
    PRINT '✓ Existing membership procedures cleaned up';
    
    -- ============================================================================
    -- LOGGING PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating membership logging procedures...';
    
    -- LogLoginAttempt: Enhanced login attempt logging
    EXEC ('
    CREATE PROCEDURE dbo.LogLoginAttempt
        @PhoneNumber NVARCHAR(18),
        @Outcome NVARCHAR(MAX),
        @IsSuccess BIT,
        @IpAddress NVARCHAR(45) = NULL,
        @UserAgent NVARCHAR(500) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        BEGIN TRY
            -- Validate phone number format
            IF dbo.ValidatePhoneNumber(@PhoneNumber) = 0
            BEGIN
                EXEC dbo.LogError 
                    @ErrorMessage = ''Invalid phone number format in LogLoginAttempt'',
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @PhoneNumber;
                RETURN;
            END
            
            -- Truncate outcome if too long
            IF LEN(@Outcome) > 255
                SET @Outcome = LEFT(@Outcome, 252) + ''...'';
            
            -- Insert login attempt record
            INSERT INTO dbo.LoginAttempts (Timestamp, PhoneNumber, Outcome, IsSuccess)
            VALUES (GETUTCDATE(), @PhoneNumber, @Outcome, @IsSuccess);
            
            -- Log audit event for failed attempts or suspicious patterns
            IF @IsSuccess = 0 OR @Outcome LIKE ''%suspicious%'' OR @Outcome LIKE ''%locked%''
            BEGIN
                EXEC dbo.LogAuditEvent 
                    @EventType = CASE WHEN @IsSuccess = 0 THEN ''LOGIN_FAILED'' ELSE ''LOGIN_SUSPICIOUS'' END,
                    @Details = @Outcome,
                    @IpAddress = @IpAddress,
                    @AdditionalData = dbo.MaskSensitiveData(@PhoneNumber, ''PHONE'');
            END
            
        END TRY
        BEGIN CATCH
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''LogLoginAttempt failed'';
        END CATCH
    END;
    ');
    
    -- LogMembershipAttempt: Enhanced membership attempt logging
    EXEC ('
    CREATE PROCEDURE dbo.LogMembershipAttempt
        @PhoneNumberId UNIQUEIDENTIFIER,
        @Outcome NVARCHAR(MAX),
        @IsSuccess BIT,
        @IpAddress NVARCHAR(45) = NULL,
        @AdditionalContext NVARCHAR(MAX) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        BEGIN TRY
            -- Validate phone number ID
            IF dbo.ValidateGuid(CAST(@PhoneNumberId AS NVARCHAR(50))) = 0
            BEGIN
                EXEC dbo.LogError 
                    @ErrorMessage = ''Invalid PhoneNumberId in LogMembershipAttempt'',
                    @ErrorSeverity = ''WARNING'';
                RETURN;
            END
            
            -- Truncate outcome if too long
            IF LEN(@Outcome) > 255
                SET @Outcome = LEFT(@Outcome, 252) + ''...'';
            
            -- Insert membership attempt record
            INSERT INTO dbo.MembershipAttempts (PhoneNumberId, Timestamp, Outcome, IsSuccess)
            VALUES (@PhoneNumberId, GETUTCDATE(), @Outcome, @IsSuccess);
            
            -- Log audit event for significant membership events
            IF @IsSuccess = 1 OR @Outcome LIKE ''%failed%'' OR @Outcome LIKE ''%blocked%''
            BEGIN
                EXEC dbo.LogAuditEvent 
                    @EventType = CASE WHEN @IsSuccess = 1 THEN ''MEMBERSHIP_SUCCESS'' ELSE ''MEMBERSHIP_FAILED'' END,
                    @Details = @Outcome,
                    @IpAddress = @IpAddress,
                    @AdditionalData = CONCAT(''PhoneNumberId:'', @PhoneNumberId, CASE WHEN @AdditionalContext IS NOT NULL THEN '', '' + @AdditionalContext ELSE '''' END);
            END
            
        END TRY
        BEGIN CATCH
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''LogMembershipAttempt failed'';
        END CATCH
    END;
    ');
    
    PRINT '✓ Membership logging procedures created';
    
    -- ============================================================================
    -- MEMBERSHIP VALIDATION
    -- ============================================================================
    
    PRINT 'Creating membership validation procedures...';
    
    -- ValidateMembershipEligibility: Comprehensive eligibility validation
    EXEC ('
    CREATE PROCEDURE dbo.ValidateMembershipEligibility
        @FlowUniqueId UNIQUEIDENTIFIER,
        @ConnectionId BIGINT,
        @OtpUniqueId UNIQUEIDENTIFIER,
        @IpAddress NVARCHAR(45) = NULL,
        @IsEligible BIT OUTPUT,
        @BlockingReason NVARCHAR(255) OUTPUT,
        @WaitTimeMinutes INT OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        SET @IsEligible = 0;
        SET @BlockingReason = NULL;
        SET @WaitTimeMinutes = 0;
        
        DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
        DECLARE @AppDeviceId UNIQUEIDENTIFIER;
        DECLARE @FlowStatus NVARCHAR(20);
        DECLARE @FlowPurpose NVARCHAR(30);
        
        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate GUIDs
            IF dbo.ValidateGuid(CAST(@FlowUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @BlockingReason = ''Invalid FlowUniqueId format'';
                RETURN;
            END
            
            IF dbo.ValidateGuid(CAST(@OtpUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @BlockingReason = ''Invalid OtpUniqueId format'';
                RETURN;
            END
            
            -- Validate IP address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @BlockingReason = ''Invalid IP address format'';
                RETURN;
            END
            
            -- ================================================================
            -- VERIFICATION FLOW VALIDATION
            -- ================================================================
            
            -- Check verification flow exists and is valid
            SELECT 
                @PhoneNumberId = pn.UniqueId,
                @AppDeviceId = vf.AppDeviceId,
                @FlowStatus = vf.Status,
                @FlowPurpose = vf.Purpose
            FROM dbo.VerificationFlows vf
            INNER JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
            WHERE vf.UniqueId = @FlowUniqueId
              AND vf.ConnectionId = @ConnectionId
              AND vf.IsDeleted = 0
              AND pn.IsDeleted = 0;
            
            IF @PhoneNumberId IS NULL
            BEGIN
                SET @BlockingReason = ''Verification flow not found or invalid'';
                RETURN;
            END
            
            -- Validate flow status
            IF @FlowStatus != ''verified''
            BEGIN
                SET @BlockingReason = CONCAT(''Verification flow not verified. Current status: '', @FlowStatus);
                RETURN;
            END
            
            -- Validate flow purpose for membership creation
            IF @FlowPurpose != ''registration''
            BEGIN
                SET @BlockingReason = CONCAT(''Invalid flow purpose for membership creation: '', @FlowPurpose);
                RETURN;
            END
            
            -- Check flow expiration
            IF EXISTS (
                SELECT 1 FROM dbo.VerificationFlows 
                WHERE UniqueId = @FlowUniqueId 
                  AND ExpiresAt < GETUTCDATE()
            )
            BEGIN
                SET @BlockingReason = ''Verification flow has expired'';
                RETURN;
            END
            
            -- ================================================================
            -- OTP VALIDATION
            -- ================================================================
            
            -- Verify OTP is valid and associated with the flow
            IF NOT EXISTS (
                SELECT 1 FROM dbo.OtpRecords 
                WHERE UniqueId = @OtpUniqueId 
                  AND FlowUniqueId = @FlowUniqueId
                  AND Status = ''verified''
                  AND IsDeleted = 0
            )
            BEGIN
                SET @BlockingReason = ''OTP not found, not verified, or not associated with flow'';
                RETURN;
            END
            
            -- ================================================================
            -- RATE LIMITING VALIDATION
            -- ================================================================
            
            DECLARE @FailedAttempts INT;
            DECLARE @EarliestFailedAttempt DATETIME2(7);
            DECLARE @AttemptWindowHours INT = CAST(dbo.GetConfigValue(''RateLimit.WindowHours'') AS INT);
            DECLARE @MaxFlowsPerHour INT = CAST(dbo.GetConfigValue(''RateLimit.MaxFlowsPerHour'') AS INT);
            
            -- Check failed membership attempts in the time window
            SELECT 
                @FailedAttempts = COUNT(*),
                @EarliestFailedAttempt = MIN(Timestamp)
            FROM dbo.MembershipAttempts
            WHERE PhoneNumberId = @PhoneNumberId
              AND IsSuccess = 0
              AND Timestamp > DATEADD(HOUR, -@AttemptWindowHours, GETUTCDATE());
            
            IF @FailedAttempts >= @MaxFlowsPerHour
            BEGIN
                SET @WaitTimeMinutes = DATEDIFF(MINUTE, GETUTCDATE(), DATEADD(HOUR, @AttemptWindowHours, @EarliestFailedAttempt));
                IF @WaitTimeMinutes < 0 SET @WaitTimeMinutes = 0;
                
                SET @BlockingReason = ''Too many failed membership attempts. Rate limit exceeded.'';
                RETURN;
            END
            
            -- ================================================================
            -- EXISTING MEMBERSHIP CHECK
            -- ================================================================
            
            -- Check if membership already exists
            IF EXISTS (
                SELECT 1 FROM dbo.Memberships 
                WHERE PhoneNumberId = @PhoneNumberId 
                  AND AppDeviceId = @AppDeviceId 
                  AND IsDeleted = 0
            )
            BEGIN
                SET @BlockingReason = ''Membership already exists for this phone number and device'';
                RETURN;
            END
            
            -- ================================================================
            -- BUSINESS RULE VALIDATION
            -- ================================================================
            
            -- Use the business rule validation framework
            DECLARE @ValidationErrors NVARCHAR(MAX);
            DECLARE @ValidationEntityData NVARCHAR(MAX) = JSON_QUERY(CONCAT(
                ''{"PhoneNumberId":"'', @PhoneNumberId, 
                ''","AppDeviceId":"'', @AppDeviceId,
                ''","IpAddress":"'', ISNULL(@IpAddress, ''''), ''"}''
            ));
            
            EXEC dbo.ValidateBusinessRules 
                @EntityType = ''Membership'',
                @EntityData = @ValidationEntityData,
                @ValidationContext = ''MEMBERSHIP_CREATE'',
                @IsValid = @IsEligible OUTPUT,
                @ValidationErrors = @ValidationErrors OUTPUT;
            
            IF @IsEligible = 0
            BEGIN
                SET @BlockingReason = ISNULL(@ValidationErrors, ''Business rule validation failed'');
                RETURN;
            END
            
            -- ================================================================
            -- SUCCESS PATH
            -- ================================================================
            
            SET @IsEligible = 1;
            SET @BlockingReason = NULL;
            
        END TRY
        BEGIN CATCH
            SET @IsEligible = 0;
            SET @BlockingReason = ''System error during eligibility validation'';
            
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''ValidateMembershipEligibility failed'';
        END CATCH
    END;
    ');
    
    PRINT '✓ Membership validation procedures created';
    
    -- ============================================================================
    -- MEMBERSHIP CREATION
    -- ============================================================================
    
    PRINT 'Creating membership creation procedures...';
    
    -- CreateMembership: Enhanced membership creation with comprehensive validation
    EXEC ('
    CREATE PROCEDURE dbo.CreateMembership
        @FlowUniqueId UNIQUEIDENTIFIER,
        @ConnectionId BIGINT,
        @OtpUniqueId UNIQUEIDENTIFIER,
        @CreationStatus NVARCHAR(20),
        @IpAddress NVARCHAR(45) = NULL,
        @UserAgent NVARCHAR(500) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        SET XACT_ABORT ON;
        
        -- Performance monitoring
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @ProcName NVARCHAR(100) = ''CreateMembership'';
        
        -- Operation variables
        DECLARE @MembershipUniqueId UNIQUEIDENTIFIER;
        DECLARE @Status NVARCHAR(20);
        DECLARE @Outcome NVARCHAR(255);
        DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
        DECLARE @AppDeviceId UNIQUEIDENTIFIER;
        DECLARE @RowsAffected INT = 0;
        
        -- Validation variables
        DECLARE @IsEligible BIT;
        DECLARE @BlockingReason NVARCHAR(255);
        DECLARE @WaitTimeMinutes INT;
        
        -- Build parameters for logging
        DECLARE @Parameters NVARCHAR(MAX) = CONCAT(
            ''FlowUniqueId='', @FlowUniqueId,
            '', ConnectionId='', @ConnectionId,
            '', CreationStatus='', @CreationStatus,
            '', IpAddress='', ISNULL(@IpAddress, ''NULL'')
        );

        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate creation status
            IF @CreationStatus NOT IN (''otp_verified'', ''secure_key_set'', ''passphrase_set'')
            BEGIN
                SET @Outcome = ''invalid_creation_status'';
                GOTO LogFailure;
            END
            
            -- Sanitize user agent
            IF LEN(@UserAgent) > 500
                SET @UserAgent = LEFT(@UserAgent, 497) + ''...'';
            
            -- ================================================================
            -- ELIGIBILITY VALIDATION
            -- ================================================================
            
            -- Check comprehensive eligibility
            EXEC dbo.ValidateMembershipEligibility
                @FlowUniqueId = @FlowUniqueId,
                @ConnectionId = @ConnectionId,
                @OtpUniqueId = @OtpUniqueId,
                @IpAddress = @IpAddress,
                @IsEligible = @IsEligible OUTPUT,
                @BlockingReason = @BlockingReason OUTPUT,
                @WaitTimeMinutes = @WaitTimeMinutes OUTPUT;
            
            IF @IsEligible = 0
            BEGIN
                SET @Outcome = ISNULL(@BlockingReason, ''eligibility_validation_failed'');
                
                -- If rate limited, include wait time
                IF @WaitTimeMinutes > 0
                    SET @Outcome = CAST(@WaitTimeMinutes AS NVARCHAR(10));
                    
                GOTO LogFailure;
            END
            
            -- Get validated flow information
            SELECT 
                @PhoneNumberId = pn.UniqueId,
                @AppDeviceId = vf.AppDeviceId
            FROM dbo.VerificationFlows vf
            INNER JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
            WHERE vf.UniqueId = @FlowUniqueId;
            
            -- ================================================================
            -- CIRCUIT BREAKER CHECK
            -- ================================================================
            
            DECLARE @CircuitOpen BIT, @CircuitError NVARCHAR(255);
            EXEC dbo.CheckCircuitBreaker ''MembershipCreate'', @CircuitOpen OUTPUT, @CircuitError OUTPUT;
            
            IF @CircuitOpen = 1
            BEGIN
                SET @Outcome = @CircuitError;
                GOTO LogFailure;
            END
            
            -- ================================================================
            -- MEMBERSHIP CREATION
            -- ================================================================
            
            -- Create the membership
            DECLARE @OutputTable TABLE (UniqueId UNIQUEIDENTIFIER, Status NVARCHAR(20), CreationStatus NVARCHAR(20));
            
            INSERT INTO dbo.Memberships (PhoneNumberId, AppDeviceId, VerificationFlowId, Status, CreationStatus)
            OUTPUT inserted.UniqueId, inserted.Status, inserted.CreationStatus INTO @OutputTable
            VALUES (@PhoneNumberId, @AppDeviceId, @FlowUniqueId, ''inactive'', @CreationStatus);
            
            SELECT @MembershipUniqueId = UniqueId, @Status = Status, @CreationStatus = CreationStatus 
            FROM @OutputTable;
            
            SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
            
            -- Deactivate the OTP record
            UPDATE dbo.OtpRecords 
            SET IsActive = 0, Status = ''used'', UpdatedAt = GETUTCDATE()
            WHERE UniqueId = @OtpUniqueId AND FlowUniqueId = @FlowUniqueId;
            
            SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
            
            -- Update verification flow status
            UPDATE dbo.VerificationFlows
            SET Status = ''completed'', UpdatedAt = GETUTCDATE()
            WHERE UniqueId = @FlowUniqueId;
            
            SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
            
            -- Clean up failed attempts on successful creation
            DELETE FROM dbo.MembershipAttempts 
            WHERE PhoneNumberId = @PhoneNumberId AND IsSuccess = 0;
            
            SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
            
            -- Record circuit breaker success
            EXEC dbo.RecordCircuitBreakerSuccess ''MembershipCreate'';
            
            -- Success outcome
            SET @Outcome = ''created'';
            
            -- Log successful creation
            EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 1, @IpAddress, @Parameters;
            
            -- Log audit event
            EXEC dbo.LogAuditEvent 
                @EventType = ''MEMBERSHIP_CREATED'',
                @Details = ''New membership created successfully'',
                @UserId = @MembershipUniqueId,
                @IpAddress = @IpAddress,
                @AdditionalData = @Parameters;
            
            GOTO ReturnResult;
            
            -- ================================================================
            -- FAILURE HANDLING
            -- ================================================================
            
            LogFailure:
            -- Record circuit breaker failure for systemic issues
            IF @Outcome LIKE ''%system%'' OR @Outcome LIKE ''%error%''
                EXEC dbo.RecordCircuitBreakerFailure ''MembershipCreate'', @Outcome;
            
            -- Log failed attempt if we have phone number
            IF @PhoneNumberId IS NOT NULL
                EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 0, @IpAddress, @Parameters;
            
            -- Log audit event for failure
            EXEC dbo.LogAuditEvent 
                @EventType = ''MEMBERSHIP_CREATION_FAILED'',
                @Details = @Outcome,
                @IpAddress = @IpAddress,
                @AdditionalData = @Parameters,
                @Success = 0;

        END TRY
        BEGIN CATCH
            SET @Outcome = ERROR_MESSAGE();
            
            -- Record circuit breaker failure
            EXEC dbo.RecordCircuitBreakerFailure ''MembershipCreate'', @Outcome;
            
            -- Log error
            EXEC dbo.LogError
                @ErrorMessage = @Outcome,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = @Parameters;
            
            -- Log failed attempt if we have phone number
            IF @PhoneNumberId IS NOT NULL
                EXEC dbo.LogMembershipAttempt @PhoneNumberId, ''system_error'', 0, @IpAddress;
        END CATCH
        
        ReturnResult:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = ''CreateMembership'',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = ''milliseconds'',
            @AdditionalData = CONCAT(''Success:'', CASE WHEN @MembershipUniqueId IS NOT NULL THEN ''1'' ELSE ''0'' END, '', RowsAffected:'', @RowsAffected);
        
        -- Return results
        SELECT 
            @MembershipUniqueId AS MembershipUniqueId,
            @Status AS Status,
            @CreationStatus AS CreationStatus,
            @Outcome AS Outcome;
    END;
    ');
    
    PRINT '✓ CreateMembership procedure created';
    
    -- ============================================================================
    -- MEMBERSHIP MANAGEMENT
    -- ============================================================================
    
    PRINT 'Creating membership management procedures...';
    
    -- UpdateMembershipSecureKey: Secure key management with validation
    EXEC ('
    CREATE PROCEDURE dbo.UpdateMembershipSecureKey
        @MembershipUniqueId UNIQUEIDENTIFIER,
        @SecureKey VARBINARY(MAX),
        @IpAddress NVARCHAR(45) = NULL,
        @UserAgent NVARCHAR(500) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        SET XACT_ABORT ON;
        
        -- Performance monitoring
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        
        DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
        DECLARE @CurrentStatus NVARCHAR(20);
        DECLARE @CurrentCreationStatus NVARCHAR(20);
        DECLARE @Success BIT = 0;
        DECLARE @Message NVARCHAR(255);
        DECLARE @RowsAffected INT = 0;

        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate membership ID
            IF dbo.ValidateGuid(CAST(@MembershipUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Message = ''Invalid MembershipUniqueId format'';
                GOTO ReturnResult;
            END
            
            -- Validate secure key
            IF @SecureKey IS NULL OR DATALENGTH(@SecureKey) = 0
            BEGIN
                SET @Message = ''Secure key cannot be empty'';
                GOTO ReturnResult;
            END
            
            -- Validate minimum key length for security
            IF DATALENGTH(@SecureKey) < 32
            BEGIN
                SET @Message = ''Secure key must be at least 32 bytes for security'';
                GOTO ReturnResult;
            END
            
            -- Validate IP address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @Message = ''Invalid IP address format'';
                GOTO ReturnResult;
            END
            
            -- Sanitize user agent
            IF LEN(@UserAgent) > 500
                SET @UserAgent = LEFT(@UserAgent, 497) + ''...'';
            
            -- ================================================================
            -- MEMBERSHIP VALIDATION
            -- ================================================================
            
            -- Check if membership exists and get current state
            SELECT 
                @PhoneNumberId = PhoneNumberId,
                @CurrentStatus = Status,
                @CurrentCreationStatus = CreationStatus
            FROM dbo.Memberships
            WHERE UniqueId = @MembershipUniqueId 
              AND IsDeleted = 0;

            IF @PhoneNumberId IS NULL
            BEGIN
                SET @Message = ''Membership not found or has been deleted'';
                GOTO ReturnResult;
            END
            
            -- Check if membership is in a state that allows key updates
            IF @CurrentStatus = ''suspended''
            BEGIN
                SET @Message = ''Cannot update secure key for suspended membership'';
                GOTO ReturnResult;
            END
            
            -- ================================================================
            -- SECURE KEY UPDATE
            -- ================================================================
            
            -- Update the membership with new secure key
            UPDATE dbo.Memberships
            SET SecureKey = @SecureKey,
                Status = ''active'',
                CreationStatus = ''secure_key_set'',
                UpdatedAt = GETUTCDATE()
            WHERE UniqueId = @MembershipUniqueId;

            SET @RowsAffected = @@ROWCOUNT;
            
            IF @RowsAffected = 0
            BEGIN
                SET @Message = ''Failed to update membership secure key'';
                GOTO ReturnResult;
            END

            -- Success
            SET @Success = 1;
            SET @Message = ''Secure key updated successfully'';
            
            -- Get updated status
            SELECT @CurrentStatus = Status, @CurrentCreationStatus = CreationStatus 
            FROM dbo.Memberships 
            WHERE UniqueId = @MembershipUniqueId;
            
            -- Log successful update
            EXEC dbo.LogMembershipAttempt @PhoneNumberId, ''secure_key_updated'', 1, @IpAddress;
            
            -- Log audit event
            EXEC dbo.LogAuditEvent 
                @EventType = ''SECURE_KEY_UPDATED'',
                @Details = ''Membership secure key updated successfully'',
                @UserId = @MembershipUniqueId,
                @IpAddress = @IpAddress;

        END TRY
        BEGIN CATCH
            SET @Message = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''UpdateMembershipSecureKey failed'';
            
            -- Log failed attempt if we have phone number
            IF @PhoneNumberId IS NOT NULL
                EXEC dbo.LogMembershipAttempt @PhoneNumberId, ''secure_key_update_failed'', 0, @IpAddress;
        END CATCH
        
        ReturnResult:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = ''UpdateMembershipSecureKey'',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = ''milliseconds'',
            @AdditionalData = CONCAT(''Success:'', @Success, '', RowsAffected:'', @RowsAffected);
        
        -- Return results
        SELECT 
            @Success AS Success,
            @Message AS Message,
            CASE WHEN @Success = 1 THEN @MembershipUniqueId ELSE NULL END AS MembershipUniqueId,
            CASE WHEN @Success = 1 THEN @CurrentStatus ELSE NULL END AS Status,
            CASE WHEN @Success = 1 THEN @CurrentCreationStatus ELSE NULL END AS CreationStatus;
    END;
    ');
    
    PRINT '✓ UpdateMembershipSecureKey procedure created';
    
    -- ============================================================================
    -- CONFIGURATION VALUES
    -- ============================================================================
    
    PRINT 'Adding membership-specific configuration values...';
    
    -- Add configuration values if they don''t exist
    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Membership.MaxLockoutDuration')
        INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
        VALUES ('Membership.MaxLockoutDuration', '1440', 'int', 'Maximum lockout duration in minutes (24 hours)', 'Security');

    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Membership.SuspiciousActivityThreshold')
        INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
        VALUES ('Membership.SuspiciousActivityThreshold', '3', 'int', 'Unique IPs threshold for suspicious activity', 'Security');

    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Membership.EnableGeoBlocking')
        INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
        VALUES ('Membership.EnableGeoBlocking', '0', 'bool', 'Enable geographic-based access blocking', 'Security');
    
    PRINT '✓ Configuration values added';
    
    -- ============================================================================
    -- PROCEDURE VALIDATION
    -- ============================================================================
    
    PRINT 'Validating membership procedures...';
    
    DECLARE @ProcedureCount INT;
    SELECT @ProcedureCount = COUNT(*)
    FROM sys.procedures p
    INNER JOIN sys.schemas s ON p.schema_id = s.schema_id
    WHERE s.name = 'dbo' 
    AND p.name IN (
        'LogLoginAttempt', 'LogMembershipAttempt', 'ValidateMembershipEligibility',
        'CreateMembership', 'UpdateMembershipSecureKey'
    );
    
    IF @ProcedureCount = 5
        PRINT '✓ All 5 membership procedures created successfully';
    ELSE
    BEGIN
        DECLARE @ErrorMsg NVARCHAR(255) = 'Expected 5 procedures, but found ' + CAST(@ProcedureCount AS NVARCHAR(10));
        RAISERROR(@ErrorMsg, 16, 1);
    END
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = @ProcedureCount
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 4.2: Membership Procedures Completed Successfully';
    PRINT 'Procedures created: ' + CAST(@ProcedureCount AS NVARCHAR(10));
    PRINT 'Features: Creation, validation, secure key management';
    PRINT 'Security: Rate limiting, eligibility validation, audit trail';
    PRINT 'Note: LoginMembership procedure will be created separately due to complexity';
    PRINT 'Next: Layer 4.3 - Verification Flow Procedures';
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
    PRINT 'ERROR in Layer 4.2: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO