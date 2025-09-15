/*
================================================================================
Layer 4.3: Verification Flow Procedures
================================================================================
Purpose: Core verification flow and OTP management procedures with enhanced security
Dependencies: Layers 1-3 (Infrastructure, Domain Tables, Constraints), Layer 4.1-4.2 (Authentication, Membership)
Execution Order: 10th - Verification workflow business logic layer

Features:
- Verification flow lifecycle management
- Enhanced OTP security with rate limiting
- Advanced flow state tracking
- Comprehensive audit logging
- Configuration-driven parameters
- Suspicious activity detection

Author: Ecliptix Development Team
Version: 1.0.0
Created: 2024-08-24
================================================================================
*/

-- Use target database
USE [EcliptixMemberships]; -- Replace with your actual database name
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Layer 4.3: Verification Flow Procedures';
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
VALUES (@DeploymentId, '03_VerificationFlowProcedures.sql', 9, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- CLEANUP EXISTING OBJECTS
    -- ============================================================================
    
    PRINT 'Cleaning up existing verification flow objects...';
    
    -- Drop procedures
    IF OBJECT_ID('dbo.InitiateVerificationFlow', 'P') IS NOT NULL DROP PROCEDURE dbo.InitiateVerificationFlow;
    IF OBJECT_ID('dbo.RequestResendOtp', 'P') IS NOT NULL DROP PROCEDURE dbo.RequestResendOtp;
    IF OBJECT_ID('dbo.InsertOtpRecord', 'P') IS NOT NULL DROP PROCEDURE dbo.InsertOtpRecord;
    IF OBJECT_ID('dbo.UpdateOtpStatus', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateOtpStatus;
    IF OBJECT_ID('dbo.UpdateVerificationFlowStatus', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateVerificationFlowStatus;
    IF OBJECT_ID('dbo.ValidateVerificationFlowEligibility', 'P') IS NOT NULL DROP PROCEDURE dbo.ValidateVerificationFlowEligibility;
    
    -- Drop functions
    IF OBJECT_ID('dbo.GetFullFlowState', 'IF') IS NOT NULL DROP FUNCTION dbo.GetFullFlowState;
    IF OBJECT_ID('dbo.GetPhoneNumber', 'IF') IS NOT NULL DROP FUNCTION dbo.GetPhoneNumber;
    
    PRINT '✓ Existing verification flow objects cleaned up';
    
    -- ============================================================================
    -- UTILITY FUNCTIONS
    -- ============================================================================
    
    PRINT 'Creating verification flow utility functions...';
    
    -- GetPhoneNumber: Retrieve phone number details
        CREATE FUNCTION dbo.GetPhoneNumber (@PhoneUniqueId UNIQUEIDENTIFIER)
    RETURNS TABLE 
    AS 
    RETURN
    (
        SELECT 
            pn.PhoneNumber,
            pn.Region,
            pn.UniqueId,
            pn.CreatedAt,
            pn.IsDeleted
        FROM dbo.PhoneNumbers AS pn 
        WHERE pn.UniqueId = @PhoneUniqueId 
          AND pn.IsDeleted = 0
    );
    
    -- GetFullFlowState: Comprehensive flow state information
        CREATE FUNCTION dbo.GetFullFlowState(@FlowUniqueId UNIQUEIDENTIFIER)
    RETURNS TABLE
    AS 
    RETURN
    (
        SELECT
            -- Flow Information
            vf.UniqueId         AS UniqueIdentifier,
            vf.AppDeviceId      AS AppDeviceIdentifier,
            vf.ConnectionId     AS ConnectId,
            vf.ExpiresAt,
            vf.Status,
            vf.Purpose,
            vf.OtpCount,
            vf.CreatedAt        AS FlowCreatedAt,
            vf.UpdatedAt        AS FlowUpdatedAt,
            
            -- Phone Number Information
            pn.UniqueId         AS PhoneNumberIdentifier,
            pn.PhoneNumber,
            pn.Region,
            
            -- Active OTP Information
            o.UniqueId          AS Otp_UniqueIdentifier,
            o.FlowUniqueId      AS Otp_FlowUniqueId,
            o.OtpHash           AS Otp_OtpHash,
            o.OtpSalt           AS Otp_OtpSalt,
            o.ExpiresAt         AS Otp_ExpiresAt,
            o.Status            AS Otp_Status,
            o.IsActive          AS Otp_IsActive,
            o.CreatedAt         AS Otp_CreatedAt,
            
            -- Security Metrics
            (SELECT COUNT(*) FROM dbo.FailedOtpAttempts foa WHERE foa.FlowUniqueId = vf.UniqueId) AS FailedAttemptCount
            
        FROM dbo.VerificationFlows AS vf
        INNER JOIN dbo.PhoneNumbers AS pn ON vf.PhoneNumberId = pn.Id
        LEFT JOIN dbo.OtpRecords AS o ON o.FlowUniqueId = vf.UniqueId 
            AND o.IsActive = 1 
            AND o.IsDeleted = 0 
            AND o.ExpiresAt > GETUTCDATE()
        WHERE vf.UniqueId = @FlowUniqueId
          AND vf.IsDeleted = 0
    );
    
    PRINT '✓ Verification flow utility functions created';
    
    -- ============================================================================
    -- VALIDATION PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating verification flow validation procedures...';
    
    -- ValidateVerificationFlowEligibility: Comprehensive eligibility validation
        CREATE PROCEDURE dbo.ValidateVerificationFlowEligibility
        @AppDeviceId UNIQUEIDENTIFIER,
        @PhoneUniqueId UNIQUEIDENTIFIER,
        @Purpose NVARCHAR(30),
        @IpAddress NVARCHAR(45) = NULL,
        @IsEligible BIT OUTPUT,
        @BlockingReason NVARCHAR(255) OUTPUT,
        @ExistingFlowId UNIQUEIDENTIFIER OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        SET @IsEligible = 0;
        SET @BlockingReason = NULL;
        SET @ExistingFlowId = NULL;
        
        DECLARE @PhoneNumberId BIGINT;
        
        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate GUIDs
            IF dbo.ValidateGuid(CAST(@AppDeviceId AS NVARCHAR(50))) = 0
            BEGIN
                SET @BlockingReason = 'Invalid AppDeviceId format';
                RETURN;
            END
            
            IF dbo.ValidateGuid(CAST(@PhoneUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @BlockingReason = 'Invalid PhoneUniqueId format';
                RETURN;
            END
            
            -- Validate purpose
            IF @Purpose NOT IN ('unspecified', 'registration', 'login', 'password_recovery', 'update_phone')
            BEGIN
                SET @BlockingReason = 'Invalid verification flow purpose';
                RETURN;
            END
            
            -- Validate IP address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @BlockingReason = 'Invalid IP address format';
                RETURN;
            END
            
            -- ================================================================
            -- PHONE NUMBER VALIDATION
            -- ================================================================
            
            -- Check if phone number exists
            SELECT @PhoneNumberId = Id 
            FROM dbo.PhoneNumbers 
            WHERE UniqueId = @PhoneUniqueId 
              AND IsDeleted = 0;
              
            IF @PhoneNumberId IS NULL
            BEGIN
                SET @BlockingReason = 'Phone number not found or has been deleted';
                RETURN;
            END
            
            -- Validate phone number format
            DECLARE @PhoneNumber NVARCHAR(18);
            SELECT @PhoneNumber = PhoneNumber FROM dbo.PhoneNumbers WHERE Id = @PhoneNumberId;
            
            IF dbo.ValidatePhoneNumber(@PhoneNumber) = 0
            BEGIN
                SET @BlockingReason = 'Invalid phone number format in database';
                RETURN;
            END
            
            -- ================================================================
            -- DEVICE VALIDATION
            -- ================================================================
            
            -- Check if app device exists
            IF NOT EXISTS (
                SELECT 1 FROM dbo.AppDevices 
                WHERE UniqueId = @AppDeviceId 
                  AND IsDeleted = 0
            )
            BEGIN
                SET @BlockingReason = 'App device not found or has been deleted';
                RETURN;
            END
            
            -- ================================================================
            -- EXISTING FLOW VALIDATION
            -- ================================================================
            
            -- Check for existing verified flow that hasn't expired
            SELECT TOP 1 @ExistingFlowId = UniqueId
            FROM dbo.VerificationFlows
            WHERE PhoneNumberId = @PhoneNumberId
              AND Status = 'verified'
              AND IsDeleted = 0
              AND ExpiresAt > GETUTCDATE()
            ORDER BY CreatedAt DESC;
            
            IF @ExistingFlowId IS NOT NULL
            BEGIN
                SET @IsEligible = 1;
                SET @BlockingReason = 'Existing verified flow found';
                RETURN;
            END
            
            -- Check for existing pending flow for same purpose and device
            SELECT TOP 1 @ExistingFlowId = UniqueId
            FROM dbo.VerificationFlows
            WHERE AppDeviceId = @AppDeviceId
              AND PhoneNumberId = @PhoneNumberId
              AND Purpose = @Purpose
              AND Status = 'pending'
              AND IsDeleted = 0
              AND ExpiresAt > GETUTCDATE()
            ORDER BY CreatedAt DESC;
            
            IF @ExistingFlowId IS NOT NULL
            BEGIN
                SET @IsEligible = 1;
                SET @BlockingReason = 'Existing pending flow found';
                RETURN;
            END
            
            
            -- ================================================================
            -- RATE LIMITING VALIDATION
            -- ================================================================
            
            -- Check global rate limit for phone number
            DECLARE @MaxFlowsPerHour INT = CAST(dbo.GetConfigValue('RateLimit.MaxFlowsPerHour') AS INT);
            DECLARE @RecentFlowCount INT;
            
            SELECT @RecentFlowCount = COUNT(*)
            FROM dbo.VerificationFlows 
            WHERE PhoneNumberId = @PhoneNumberId
              AND CreatedAt > DATEADD(HOUR, -1, GETUTCDATE());
              
            IF @RecentFlowCount >= @MaxFlowsPerHour
            BEGIN
                SET @BlockingReason = 'Rate limit exceeded: too many verification flows in the last hour';
                
                -- Log rate limiting event
                EXEC dbo.LogAuditEvent 
                    @EventType = 'VERIFICATION_RATE_LIMITED',
                    @Details = CONCAT('Rate limit exceeded: ', @RecentFlowCount, ' flows in last hour'),
                    @IpAddress = @IpAddress,
                    @AdditionalData = CONCAT('PhoneNumber:', dbo.MaskSensitiveData(@PhoneNumber, 'PHONE'), ', MaxFlowsPerHour:', @MaxFlowsPerHour);
                    
                RETURN;
            END
            
            -- ================================================================
            -- BUSINESS RULE VALIDATION
            -- ================================================================
            
            -- Use business rule validation framework
            DECLARE @ValidationErrors NVARCHAR(MAX);
            DECLARE @ValidationEntityData NVARCHAR(MAX) = CONCAT(
                '{"PhoneNumber":"', @PhoneNumber, 
                '","Purpose":"', @Purpose,
                '","IpAddress":"', ISNULL(@IpAddress, ''), '"}'
            );
            
            EXEC dbo.ValidateBusinessRules 
                @EntityType = 'PhoneNumber',
                @EntityData = @ValidationEntityData,
                @ValidationContext = 'VERIFICATION_REQUEST',
                @IsValid = @IsEligible OUTPUT,
                @ValidationErrors = @ValidationErrors OUTPUT;
            
            IF @IsEligible = 0
            BEGIN
                SET @BlockingReason = ISNULL(@ValidationErrors, 'Business rule validation failed');
                RETURN;
            END
            
            -- ================================================================
            -- SUCCESS PATH
            -- ================================================================
            
            SET @IsEligible = 1;
            SET @BlockingReason = 'Eligible for new verification flow';
            
        END TRY
        BEGIN CATCH
            SET @IsEligible = 0;
            SET @BlockingReason = 'System error during eligibility validation';
            
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = 'ERROR',
                @AdditionalInfo = 'ValidateVerificationFlowEligibility failed';
        END CATCH
    END;
    
    PRINT '✓ Verification flow validation procedures created';
    
    -- ============================================================================
    -- VERIFICATION FLOW MANAGEMENT
    -- ============================================================================
    
    PRINT 'Creating verification flow management procedures...';
    
    -- InitiateVerificationFlow: Enhanced flow creation with comprehensive validation
        CREATE PROCEDURE dbo.InitiateVerificationFlow
        @AppDeviceId UNIQUEIDENTIFIER,
        @PhoneUniqueId UNIQUEIDENTIFIER,
        @Purpose NVARCHAR(30),
        @ConnectionId BIGINT = NULL,
        @IpAddress NVARCHAR(45) = NULL,
        @UserAgent NVARCHAR(500) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        SET XACT_ABORT ON;
        
        -- Performance monitoring
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @ProcName NVARCHAR(100) = 'InitiateVerificationFlow';
        
        DECLARE @PhoneNumberId BIGINT;
        DECLARE @NewFlowUniqueId UNIQUEIDENTIFIER;
        DECLARE @ExpiresAt DATETIME2(7);
        DECLARE @Outcome NVARCHAR(50);
        DECLARE @IsEligible BIT;
        DECLARE @BlockingReason NVARCHAR(255);
        DECLARE @ExistingFlowId UNIQUEIDENTIFIER;
        DECLARE @RowsAffected INT = 0;
        
        -- Build parameters for logging
        DECLARE @Parameters NVARCHAR(MAX) = CONCAT(
            'AppDeviceId=', @AppDeviceId,
            ', PhoneUniqueId=', @PhoneUniqueId,
            ', Purpose=', @Purpose,
            ', ConnectionId=', ISNULL(CAST(@ConnectionId AS NVARCHAR(20)), 'NULL')
        );

        BEGIN TRY
            -- ================================================================
            -- ELIGIBILITY VALIDATION
            -- ================================================================
            
            EXEC dbo.ValidateVerificationFlowEligibility
                @AppDeviceId = @AppDeviceId,
                @PhoneUniqueId = @PhoneUniqueId,
                @Purpose = @Purpose,
                @IpAddress = @IpAddress,
                @IsEligible = @IsEligible OUTPUT,
                @BlockingReason = @BlockingReason OUTPUT,
                @ExistingFlowId = @ExistingFlowId OUTPUT;
            
            -- Handle existing flow scenarios
            IF @IsEligible = 1 AND @ExistingFlowId IS NOT NULL
            BEGIN
                IF @BlockingReason = 'Existing verified flow found'
                BEGIN
                    SET @Outcome = 'verified';
                    GOTO ReturnExistingFlow;
                END
                ELSE IF @BlockingReason = 'Existing pending flow found'
                BEGIN
                    SET @Outcome = 'retrieved';
                    GOTO ReturnExistingFlow;
                END
                ELSE IF @BlockingReason = 'Existing expired flow can be reactivated'
                BEGIN
                    SET @Outcome = 'reactivated';
                    GOTO ReturnExistingFlow;
                END
            END
            
            -- ================================================================
            -- ATOMIC EXPIRED FLOW REACTIVATION
            -- ================================================================
            
            -- Try atomic reactivation of expired flow with proper locking
            DECLARE @ReactivatedFlowId UNIQUEIDENTIFIER;
            DECLARE @ReactivationExpiry DATETIME2(7) = DATEADD(MINUTE, 15, GETUTCDATE());
            
            -- Atomic operation: find, lock, and update expired flow if exists
            UPDATE TOP(1) dbo.VerificationFlows 
            SET @ReactivatedFlowId = UniqueId,
                Status = 'pending',
                ExpiresAt = @ReactivationExpiry,
                UpdatedAt = GETUTCDATE(),
                OtpCount = 0
            WHERE AppDeviceId = @AppDeviceId
              AND PhoneNumberId = (SELECT Id FROM dbo.PhoneNumbers WHERE UniqueId = @PhoneUniqueId AND IsDeleted = 0)
              AND Purpose = @Purpose
              AND Status = 'expired'
              AND IsDeleted = 0
              AND CreatedAt > DATEADD(HOUR, -24, GETUTCDATE());
            
            -- If we successfully reactivated a flow
            IF @ReactivatedFlowId IS NOT NULL
            BEGIN
                -- Clean up old OTPs atomically in same transaction
                UPDATE dbo.OtpRecords 
                SET Status = 'expired',
                    UpdatedAt = GETUTCDATE()
                WHERE FlowUniqueId = @ReactivatedFlowId 
                  AND Status IN ('pending', 'unused');
                
                SET @ExistingFlowId = @ReactivatedFlowId;
                SET @Outcome = 'reactivated';
                GOTO ReturnExistingFlow;
            END
            
            -- Handle ineligibility
            IF @IsEligible = 0
            BEGIN
                SET @Outcome = 'ineligible';
                
                -- Determine specific outcome based on blocking reason
                IF @BlockingReason LIKE '%rate limit%'
                    SET @Outcome = 'global_rate_limit_exceeded';
                ELSE IF @BlockingReason LIKE '%not found%'
                    SET @Outcome = 'phone_not_found';
                ELSE IF @BlockingReason LIKE '%invalid%'
                    SET @Outcome = 'invalid_request';
                
                GOTO ReturnOutcome;
            END
            
            -- ================================================================
            -- CIRCUIT BREAKER CHECK
            -- ================================================================
            
            DECLARE @CircuitOpen BIT, @CircuitError NVARCHAR(255);
            EXEC dbo.CheckCircuitBreaker 'VerificationFlowCreate', @CircuitOpen OUTPUT, @CircuitError OUTPUT;
            
            IF @CircuitOpen = 1
            BEGIN
                SET @Outcome = 'service_unavailable';
                GOTO ReturnOutcome;
            END
            
            -- ================================================================
            -- NEW FLOW CREATION
            -- ================================================================
            
            -- Get phone number ID
            SELECT @PhoneNumberId = Id 
            FROM dbo.PhoneNumbers 
            WHERE UniqueId = @PhoneUniqueId AND IsDeleted = 0;
            
            -- Expire old flows for same device/phone/purpose
            UPDATE dbo.VerificationFlows
            SET Status = 'expired', UpdatedAt = GETUTCDATE()
            WHERE AppDeviceId = @AppDeviceId 
              AND PhoneNumberId = @PhoneNumberId 
              AND Purpose = @Purpose 
              AND Status = 'pending' 
              AND IsDeleted = 0 
              AND ExpiresAt <= GETUTCDATE();
            
            SET @RowsAffected = @@ROWCOUNT;
            
            -- Create new verification flow
            SET @NewFlowUniqueId = NEWID();
            DECLARE @DefaultExpirationMinutes INT = CAST(dbo.GetConfigValue('VerificationFlow.DefaultExpirationMinutes') AS INT);
            -- Ensure minimum expiration time of 1 minute if config value is invalid or missing
            IF @DefaultExpirationMinutes IS NULL OR @DefaultExpirationMinutes <= 0
                SET @DefaultExpirationMinutes = 1;
            SET @ExpiresAt = DATEADD(MINUTE, @DefaultExpirationMinutes, GETUTCDATE());
            
            INSERT INTO dbo.VerificationFlows (
                UniqueId, AppDeviceId, PhoneNumberId, Purpose, 
                ExpiresAt, ConnectionId, OtpCount
            )
            VALUES (
                @NewFlowUniqueId, @AppDeviceId, @PhoneNumberId, @Purpose,
                @ExpiresAt, @ConnectionId, 0
            );
            
            SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
            
            -- Record circuit breaker success
            EXEC dbo.RecordCircuitBreakerSuccess 'VerificationFlowCreate';
            
            SET @Outcome = 'created';
            SET @ExistingFlowId = @NewFlowUniqueId;
            
            -- Log successful creation
            EXEC dbo.LogAuditEvent 
                @EventType = 'VERIFICATION_FLOW_CREATED',
                @Details = 'New verification flow created successfully',
                @IpAddress = @IpAddress,
                @AdditionalData = @Parameters;
            
            GOTO ReturnExistingFlow;
            
        END TRY
        BEGIN CATCH
            SET @Outcome = 'system_error';
            
            -- Record circuit breaker failure
            EXEC dbo.RecordCircuitBreakerFailure 'VerificationFlowCreate', ERROR_MESSAGE();
            
            -- Log error
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = 'ERROR',
                @AdditionalInfo = @Parameters;
            
            GOTO ReturnOutcome;
        END CATCH
        
        ReturnExistingFlow:
        -- Return full flow state
        SELECT *, @Outcome AS Outcome 
        FROM dbo.GetFullFlowState(@ExistingFlowId);
        GOTO LogPerformance;
        
        ReturnOutcome:
        -- Return outcome only
        SELECT @Outcome AS Outcome;
        
        LogPerformance:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = 'InitiateVerificationFlow',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = 'milliseconds',
            @AdditionalData = CONCAT('Outcome:', @Outcome, ', RowsAffected:', @RowsAffected);
    END;
    
    PRINT '✓ InitiateVerificationFlow procedure created';
    
    -- ============================================================================
    -- OTP MANAGEMENT PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating OTP management procedures...';
    
    -- RequestResendOtp: Enhanced OTP resend with rate limiting
        CREATE PROCEDURE dbo.RequestResendOtp
        @FlowUniqueId UNIQUEIDENTIFIER,
        @IpAddress NVARCHAR(45) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @Outcome NVARCHAR(50);
        DECLARE @OtpCount SMALLINT;
        DECLARE @SessionExpiresAt DATETIME2(7);
        DECLARE @LastOtpTimestamp DATETIME2(7);
        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
        
        -- Configuration-driven parameters
        DECLARE @MaxOtpAttempts INT = CAST(dbo.GetConfigValue('OTP.MaxAttempts') AS INT);
        DECLARE @MinResendIntervalSeconds INT = CAST(dbo.GetConfigValue('OTP.ResendCooldownSeconds') AS INT);

        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate flow ID
            IF dbo.ValidateGuid(CAST(@FlowUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Outcome = 'invalid_flow_id';
                GOTO ReturnResult;
            END
            
            -- Validate IP address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @Outcome = 'invalid_ip_address';
                GOTO ReturnResult;
            END
            
            -- ================================================================
            -- FLOW VALIDATION
            -- ================================================================
            
            -- Get flow information
            SELECT
                @OtpCount = OtpCount,
                @SessionExpiresAt = ExpiresAt
            FROM dbo.VerificationFlows
            WHERE UniqueId = @FlowUniqueId 
              AND IsDeleted = 0 
              AND Status = 'pending';

            IF @SessionExpiresAt IS NULL
            BEGIN
                SET @Outcome = 'flow_not_found_or_invalid';
                GOTO ReturnResult;
            END

            -- Check flow expiration
            IF @CurrentTime >= @SessionExpiresAt
            BEGIN
                UPDATE dbo.VerificationFlows 
                SET Status = 'expired', UpdatedAt = @CurrentTime
                WHERE UniqueId = @FlowUniqueId;
                
                SET @Outcome = 'flow_expired';
                GOTO ReturnResult;
            END
            
            -- Check OTP attempt limit
            IF @OtpCount >= @MaxOtpAttempts
            BEGIN
                UPDATE dbo.VerificationFlows 
                SET Status = 'failed', UpdatedAt = @CurrentTime
                WHERE UniqueId = @FlowUniqueId;
                
                SET @Outcome = 'max_otp_attempts_reached';
                GOTO ReturnResult;
            END
            
            -- ================================================================
            -- RATE LIMITING CHECK
            -- ================================================================
            
            -- Get last OTP timestamp
            SELECT @LastOtpTimestamp = MAX(CreatedAt)
            FROM dbo.OtpRecords
            WHERE FlowUniqueId = @FlowUniqueId
              AND IsDeleted = 0;

            -- Check resend cooldown
            IF @LastOtpTimestamp IS NOT NULL 
               AND DATEDIFF(SECOND, @LastOtpTimestamp, @CurrentTime) < @MinResendIntervalSeconds
            BEGIN
                SET @Outcome = 'resend_cooldown_active';
                GOTO ReturnResult;
            END
            
            -- ================================================================
            -- SUCCESS PATH
            -- ================================================================
            
            SET @Outcome = 'resend_allowed';
            
            -- Log resend request
            EXEC dbo.LogAuditEvent 
                @EventType = 'OTP_RESEND_REQUESTED',
                @Details = 'OTP resend request approved',
                @IpAddress = @IpAddress,
                @AdditionalData = CONCAT('FlowUniqueId:', @FlowUniqueId, ', OtpCount:', @OtpCount);

        END TRY
        BEGIN CATCH
            SET @Outcome = 'system_error';
            
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = 'ERROR',
                @AdditionalInfo = 'RequestResendOtp failed';
        END CATCH
        
        ReturnResult:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = 'RequestResendOtp',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = 'milliseconds',
            @AdditionalData = CONCAT('Outcome:', @Outcome);
        
        SELECT @Outcome AS Outcome;
    END;
    
    PRINT '✓ RequestResendOtp procedure created';
    
    -- ============================================================================
    -- CONFIGURATION VALUES
    -- ============================================================================
    
    PRINT 'Adding verification flow configuration values...';
    
    -- Add configuration values if they don''t exist
    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'VerificationFlow.DefaultExpirationMinutes')
        INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
        VALUES ('VerificationFlow.DefaultExpirationMinutes', '1', 'int', 'Default verification flow expiration in minutes', 'Security');

    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'OTP.EnableRateLimitTracking')
        INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
        VALUES ('OTP.EnableRateLimitTracking', '1', 'bool', 'Enable OTP rate limit tracking and enforcement', 'Security');
    
    PRINT '✓ Configuration values added';
    
    -- ============================================================================
    -- PROCEDURE VALIDATION
    -- ============================================================================
    
    PRINT 'Validating verification flow procedures...';
    
    DECLARE @ProcedureCount INT;
    SELECT @ProcedureCount = COUNT(*)
    FROM sys.procedures p
    INNER JOIN sys.schemas s ON p.schema_id = s.schema_id
    WHERE s.name = 'dbo' 
    AND p.name IN (
        'ValidateVerificationFlowEligibility', 'InitiateVerificationFlow',
        'RequestResendOtp'
    );
    
    DECLARE @FunctionCount INT;
    SELECT @FunctionCount = COUNT(*)
    FROM sys.objects o
    WHERE o.type IN ('FN', 'IF', 'TF') 
    AND SCHEMA_NAME(o.schema_id) = 'dbo'
    AND o.name IN ('GetFullFlowState', 'GetPhoneNumber');
    
    IF @ProcedureCount = 3 AND @FunctionCount = 2
        PRINT '✓ All 3 procedures and 2 functions created successfully';
    ELSE
    BEGIN
        DECLARE @ErrorMsg NVARCHAR(255) = 'Expected 3 procedures and 2 functions, but found ' + 
                                          CAST(@ProcedureCount AS NVARCHAR(10)) + ' procedures and ' +
                                          CAST(@FunctionCount AS NVARCHAR(10)) + ' functions';
        RAISERROR(@ErrorMsg, 16, 1);
    END
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = @ProcedureCount + @FunctionCount
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 4.3: Verification Flow Procedures Completed Successfully';
    PRINT 'Procedures created: ' + CAST(@ProcedureCount AS NVARCHAR(10));
    PRINT 'Functions created: ' + CAST(@FunctionCount AS NVARCHAR(10));
    PRINT 'Features: Flow initiation, OTP management, rate limiting';
    PRINT 'Security: Eligibility validation, audit trail, circuit breakers';
    PRINT 'Note: Additional OTP procedures (InsertOtpRecord, UpdateOtpStatus) in next layer';
    PRINT 'Next: Layer 4.4 - Complete remaining business procedures';
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
    PRINT 'ERROR in Layer 4.3: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO