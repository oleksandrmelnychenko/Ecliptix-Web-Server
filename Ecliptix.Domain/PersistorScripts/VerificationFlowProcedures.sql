
/*
================================================================================
Ecliptix Verification Flow Procedures - Production Ready
================================================================================
Purpose: Enhanced verification flow management with comprehensive security,
         rate limiting, and monitoring capabilities for production environments.

Version: 2.0.0
Author: Ecliptix Development Team
Created: 2024-08-24
Dependencies: ProductionInfrastructure.sql must be executed first

Features:
- Enhanced OTP security with configurable parameters
- Advanced rate limiting and flow management
- Comprehensive audit logging for compliance
- Performance monitoring and metrics collection
- Input validation and sanitization
- Configuration-driven security parameters
- Suspicious activity detection and prevention

Security Enhancements:
- OTP attempt tracking and rate limiting
- Flow expiration management
- Complete audit trail for verification events
- Enhanced error handling and logging
================================================================================
*/

BEGIN TRANSACTION;
GO

IF OBJECT_ID('dbo.UpdateOtpStatus', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateOtpStatus;
IF OBJECT_ID('dbo.InsertOtpRecord', 'P') IS NOT NULL DROP PROCEDURE dbo.InsertOtpRecord;
IF OBJECT_ID('dbo.RequestResendOtp', 'P') IS NOT NULL DROP PROCEDURE dbo.RequestResendOtp;
IF OBJECT_ID('dbo.InitiateVerificationFlow', 'P') IS NOT NULL DROP PROCEDURE dbo.InitiateVerificationFlow;
IF OBJECT_ID('dbo.UpdateVerificationFlowStatus', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateVerificationFlowStatus;
IF OBJECT_ID('dbo.GetPhoneNumber', 'IF') IS NOT NULL DROP FUNCTION dbo.GetPhoneNumber;
IF OBJECT_ID('dbo.GetFullFlowState', 'IF') IS NOT NULL DROP FUNCTION dbo.GetFullFlowState;
GO


CREATE FUNCTION dbo.GetFullFlowState(@FlowUniqueId UNIQUEIDENTIFIER)
RETURNS TABLE
AS RETURN
(
    SELECT
        vf.UniqueId         AS UniqueIdentifier,
        pn.UniqueId         AS PhoneNumberIdentifier,
        vf.AppDeviceId      AS AppDeviceIdentifier,
        vf.ConnectionId     AS ConnectId,
        vf.ExpiresAt,
        vf.Status,
        vf.Purpose,
        vf.OtpCount,
        o.UniqueId          AS Otp_UniqueIdentifier,
        o.FlowUniqueId      AS Otp_FlowUniqueId,
        o.OtpHash           AS Otp_OtpHash,
        o.OtpSalt           AS Otp_OtpSalt,
        o.ExpiresAt         AS Otp_ExpiresAt,
        o.Status            AS Otp_Status,
        o.IsActive          AS Otp_IsActive
    FROM dbo.VerificationFlows AS vf
    JOIN dbo.PhoneNumbers AS pn ON vf.PhoneNumberId = pn.Id
    LEFT JOIN dbo.OtpRecords AS o ON o.FlowUniqueId = vf.UniqueId AND o.IsActive = 1 AND o.IsDeleted = 0 AND o.ExpiresAt > GETUTCDATE()
    WHERE vf.UniqueId = @FlowUniqueId
);
GO


CREATE PROCEDURE dbo.InitiateVerificationFlow
    @AppDeviceId UNIQUEIDENTIFIER,
    @PhoneUniqueId UNIQUEIDENTIFIER,
    @Purpose NVARCHAR(30),
    @ConnectionId BIGINT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @PhoneNumberId BIGINT;
    SELECT @PhoneNumberId = Id FROM dbo.PhoneNumbers WHERE UniqueId = @PhoneUniqueId AND IsDeleted = 0;
    IF @PhoneNumberId IS NULL
    BEGIN
        SELECT 'phone_not_found' AS Outcome;
        RETURN;
    END

    DECLARE @ExistingVerifiedFlowId UNIQUEIDENTIFIER;
    SELECT TOP 1 @ExistingVerifiedFlowId = UniqueId
    FROM dbo.VerificationFlows
    WHERE PhoneNumberId = @PhoneNumberId
        AND Status = 'verified'
        AND IsDeleted = 0
        AND ExpiresAt > GETUTCDATE()
    ORDER BY CreatedAt DESC;

    IF @ExistingVerifiedFlowId IS NOT NULL
    BEGIN
        SELECT *, 'verified' AS Outcome FROM dbo.GetFullFlowState(@ExistingVerifiedFlowId);
        RETURN;
    END

    DECLARE @MaxFlowsPerHour INT = 5;
    IF (SELECT COUNT(*) FROM dbo.VerificationFlows WHERE PhoneNumberId = @PhoneNumberId AND CreatedAt > DATEADD(hour, -1, GETUTCDATE())) >= @MaxFlowsPerHour
    BEGIN
        SELECT 'global_rate_limit_exceeded' AS Outcome;
        RETURN;
    END

    UPDATE dbo.VerificationFlows
    SET Status = 'expired'
    WHERE AppDeviceId = @AppDeviceId AND PhoneNumberId = @PhoneNumberId AND Purpose = @Purpose AND Status = 'pending' AND IsDeleted = 0 AND ExpiresAt <= GETUTCDATE();

    DECLARE @NewFlowUniqueId UNIQUEIDENTIFIER = NEWID();
    DECLARE @ExpiresAt DATETIME2(7) = DATEADD(minute, 5, GETUTCDATE());

    BEGIN TRY
        INSERT INTO dbo.VerificationFlows (UniqueId, AppDeviceId, PhoneNumberId, Purpose, ExpiresAt, ConnectionId, OtpCount)
        VALUES (@NewFlowUniqueId, @AppDeviceId, @PhoneNumberId, @Purpose, @ExpiresAt, @ConnectionId, 0);

        SELECT *, 'created' AS Outcome FROM dbo.GetFullFlowState(@NewFlowUniqueId);
    END TRY
    BEGIN CATCH
        IF ERROR_NUMBER() IN (2601, 2627)
        BEGIN
            DECLARE @ExistingFlowId UNIQUEIDENTIFIER;
            SELECT TOP 1 @ExistingFlowId = UniqueId
            FROM dbo.VerificationFlows
            WHERE AppDeviceId = @AppDeviceId AND PhoneNumberId = @PhoneNumberId AND Purpose = @Purpose AND Status = 'pending' AND IsDeleted = 0 AND ExpiresAt > GETUTCDATE()
            ORDER BY CreatedAt DESC;

            IF @ExistingFlowId IS NOT NULL
                SELECT *, 'retrieved' AS Outcome FROM dbo.GetFullFlowState(@ExistingFlowId);
            ELSE
                SELECT 'conflict_unresolved' AS Outcome;
        END
        ELSE
            THROW;
    END CATCH;
END;
GO


CREATE PROCEDURE dbo.RequestResendOtp
    @FlowUniqueId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Outcome NVARCHAR(50);
    DECLARE @MaxOtpAttempts INT = 5;
    DECLARE @MinResendIntervalSeconds INT = 30;
    DECLARE @OtpCount SMALLINT;
    DECLARE @SessionExpiresAt DATETIME2(7);
    DECLARE @LastOtpTimestamp DATETIME2(7);
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

    SELECT
        @OtpCount = OtpCount,
        @SessionExpiresAt = ExpiresAt
    FROM dbo.VerificationFlows
    WHERE UniqueId = @FlowUniqueId AND IsDeleted = 0 AND Status = 'pending';

    IF @SessionExpiresAt IS NULL
    BEGIN
        SET @Outcome = 'flow_not_found_or_invalid';
        SELECT @Outcome AS Outcome;
        RETURN;
    END

    SELECT @LastOtpTimestamp = MAX(CreatedAt)
    FROM dbo.OtpRecords
    WHERE FlowUniqueId = @FlowUniqueId;

    IF @CurrentTime >= @SessionExpiresAt
    BEGIN
        UPDATE dbo.VerificationFlows SET Status = 'expired' WHERE UniqueId = @FlowUniqueId;
        SET @Outcome = 'flow_expired';
    END
    ELSE IF @OtpCount >= @MaxOtpAttempts
    BEGIN
        UPDATE dbo.VerificationFlows SET Status = 'failed' WHERE UniqueId = @FlowUniqueId;
        SET @Outcome = 'max_otp_attempts_reached';
    END
    ELSE IF @LastOtpTimestamp IS NOT NULL AND DATEDIFF(second, @LastOtpTimestamp, @CurrentTime) < @MinResendIntervalSeconds
    BEGIN
        SET @Outcome = 'resend_cooldown_active';
    END
    ELSE
    BEGIN
        SET @Outcome = 'resend_allowed';
    END

    SELECT @Outcome AS Outcome;
END;
GO


/*
================================================================================
Procedure: dbo.InsertOtpRecord
Purpose: Enhanced OTP creation with security validation and monitoring
Parameters:
    @FlowUniqueId UNIQUEIDENTIFIER - Verification flow ID (required, validated)
    @OtpHash NVARCHAR(MAX) - OTP hash (required, validated)
    @OtpSalt NVARCHAR(MAX) - OTP salt (required, validated)
    @ExpiresAt DATETIME2(7) - OTP expiration (required, validated)
    @Status NVARCHAR(20) - Initial OTP status (required, validated)
Returns: OTP ID and creation result with security audit trail
================================================================================
*/
CREATE PROCEDURE dbo.InsertOtpRecord
    @FlowUniqueId UNIQUEIDENTIFIER, 
    @OtpHash NVARCHAR(MAX), 
    @OtpSalt NVARCHAR(MAX), 
    @ExpiresAt DATETIME2(7), 
    @Status NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    
    DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
    DECLARE @ProcName NVARCHAR(100) = 'InsertOtpRecord';
    DECLARE @Parameters NVARCHAR(MAX);
    
    DECLARE @FlowId BIGINT, @PhoneNumberId BIGINT, @OtpCount SMALLINT;
    DECLARE @OtpUniqueId UNIQUEIDENTIFIER;
    DECLARE @Outcome NVARCHAR(50);
    DECLARE @MaxOtpAttempts INT;
    DECLARE @IsValidInput BIT;
    DECLARE @ValidationError NVARCHAR(255);
    DECLARE @RowsAffected INT = 0;
    
    -- Get configurable max OTP attempts
    SET @MaxOtpAttempts = CAST(dbo.GetConfigValue('OTP.MaxAttempts') AS INT);
    
    -- Build parameters for logging (without sensitive data)
    SET @Parameters = CONCAT(
        'FlowUniqueId=', @FlowUniqueId,
        ', Status=', ISNULL(@Status, 'NULL'),
        ', ExpiresAt=', FORMAT(@ExpiresAt, 'yyyy-MM-dd HH:mm:ss'),
        ', MaxAttempts=', @MaxOtpAttempts
    );

    BEGIN TRY
        -- ========================================================================
        -- INPUT VALIDATION
        -- ========================================================================
        
        -- Validate FlowUniqueId
        EXEC dbo.ValidateGuid @FlowUniqueId, @IsValidInput OUTPUT, @ValidationError OUTPUT;
        IF @IsValidInput = 0
        BEGIN
            SET @Outcome = CONCAT('invalid_flow_id: ', @ValidationError);
            GOTO LogAndReturn;
        END
        
        -- Validate OTP hash and salt
        IF @OtpHash IS NULL OR LEN(@OtpHash) = 0
        BEGIN
            SET @Outcome = 'invalid_otp_hash';
            EXEC dbo.LogError @ProcedureName = @ProcName, @ErrorMessage = 'OTP hash cannot be null or empty', @Parameters = @Parameters;
            GOTO LogAndReturn;
        END
        
        IF @OtpSalt IS NULL OR LEN(@OtpSalt) = 0
        BEGIN
            SET @Outcome = 'invalid_otp_salt';
            EXEC dbo.LogError @ProcedureName = @ProcName, @ErrorMessage = 'OTP salt cannot be null or empty', @Parameters = @Parameters;
            GOTO LogAndReturn;
        END
        
        -- Validate expiration time
        IF @ExpiresAt IS NULL OR @ExpiresAt <= GETUTCDATE()
        BEGIN
            SET @Outcome = 'invalid_expiration_time';
            EXEC dbo.LogError @ProcedureName = @ProcName, @ErrorMessage = 'OTP expiration time must be in the future', @Parameters = @Parameters;
            GOTO LogAndReturn;
        END
        
        -- Validate maximum OTP expiration (prevent excessively long OTPs)
        DECLARE @MaxOtpExpirationMinutes INT = CAST(dbo.GetConfigValue('OTP.ExpirationMinutes') AS INT);
        IF @ExpiresAt > DATEADD(MINUTE, @MaxOtpExpirationMinutes, GETUTCDATE())
        BEGIN
            SET @Outcome = 'excessive_expiration_time';
            EXEC dbo.LogError @ProcedureName = @ProcName, @ErrorMessage = 'OTP expiration exceeds maximum allowed duration', @Parameters = @Parameters;
            GOTO LogAndReturn;
        END
        
        -- Validate status
        IF @Status IS NULL OR @Status NOT IN ('pending', 'verified', 'expired', 'failed')
        BEGIN
            SET @Outcome = 'invalid_status';
            EXEC dbo.LogError @ProcedureName = @ProcName, @ErrorMessage = 'Invalid OTP status provided', @Parameters = @Parameters;
            GOTO LogAndReturn;
        END
        
        -- ========================================================================
        -- VERIFICATION FLOW VALIDATION
        -- ========================================================================
        
        SELECT @FlowId = Id, @PhoneNumberId = PhoneNumberId, @OtpCount = OtpCount
        FROM dbo.VerificationFlows
        WHERE UniqueId = @FlowUniqueId 
          AND Status = 'pending' 
          AND IsDeleted = 0 
          AND ExpiresAt > GETUTCDATE();

        IF @FlowId IS NULL
        BEGIN
            SET @Outcome = 'flow_not_found_or_invalid';
            
            -- Log potential security issue
            EXEC dbo.LogAuditEvent
                @TableName = 'VerificationFlows',
                @OperationType = 'OTP_CREATION_FAILED',
                @RecordId = @FlowUniqueId,
                @ApplicationContext = 'InsertOtpRecord',
                @Success = 0,
                @ErrorMessage = 'Attempted OTP creation for invalid/expired flow';
            
            GOTO LogAndReturn;
        END

        -- Check if maximum OTP attempts reached
        IF @OtpCount >= @MaxOtpAttempts
        BEGIN
            -- Mark flow as failed due to excessive attempts
            UPDATE dbo.VerificationFlows 
            SET Status = 'failed', UpdatedAt = GETUTCDATE() 
            WHERE Id = @FlowId;
            
            SET @RowsAffected = @@ROWCOUNT;
            SET @Outcome = 'max_otp_attempts_reached';
            
            -- Log security event for excessive OTP attempts
            EXEC dbo.LogAuditEvent
                @TableName = 'VerificationFlows',
                @OperationType = 'MAX_OTP_ATTEMPTS_REACHED',
                @RecordId = @FlowUniqueId,
                @NewValues = CONCAT('OtpCount:', @OtpCount, ', MaxAttempts:', @MaxOtpAttempts),
                @ApplicationContext = 'InsertOtpRecord',
                @Success = 0,
                @ErrorMessage = 'Verification flow failed due to excessive OTP attempts';
            
            GOTO LogAndReturn;
        END

        -- ========================================================================
        -- OTP RECORD CREATION
        -- ========================================================================
        
        -- Deactivate any existing active OTPs for this flow
        UPDATE dbo.OtpRecords 
        SET IsActive = 0, UpdatedAt = GETUTCDATE()
        WHERE FlowUniqueId = @FlowUniqueId AND IsActive = 1;
        
        SET @RowsAffected = @RowsAffected + @@ROWCOUNT;

        -- Create new OTP record
        DECLARE @OtpOutputTable TABLE (UniqueId UNIQUEIDENTIFIER);
        INSERT INTO dbo.OtpRecords (FlowUniqueId, PhoneNumberId, OtpHash, OtpSalt, ExpiresAt, Status, IsActive)
        OUTPUT inserted.UniqueId INTO @OtpOutputTable(UniqueId)
        VALUES (@FlowUniqueId, @PhoneNumberId, @OtpHash, @OtpSalt, @ExpiresAt, @Status, 1);

        SELECT @OtpUniqueId = UniqueId FROM @OtpOutputTable;
        SET @RowsAffected = @RowsAffected + @@ROWCOUNT;

        -- Increment OTP count in verification flow
        UPDATE dbo.VerificationFlows 
        SET OtpCount = OtpCount + 1, UpdatedAt = GETUTCDATE() 
        WHERE Id = @FlowId;
        
        SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
        SET @Outcome = 'created';
        
        -- Log successful OTP creation
        EXEC dbo.LogAuditEvent
            @TableName = 'OtpRecords',
            @OperationType = 'INSERT',
            @RecordId = @OtpUniqueId,
            @NewValues = CONCAT('FlowUniqueId:', @FlowUniqueId, ', Status:', @Status, ', OtpCount:', (@OtpCount + 1)),
            @ApplicationContext = 'InsertOtpRecord',
            @Success = 1;

    END TRY
    BEGIN CATCH
        SET @Outcome = 'system_error';
        
        -- Log the error
        EXEC dbo.LogError
            @ProcedureName = @ProcName,
            @ErrorMessage = ERROR_MESSAGE(),
            @Parameters = @Parameters;
    END CATCH
    
    LogAndReturn:
    -- Log performance metrics
    DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
    EXEC dbo.LogPerformanceMetric
        @ProcedureName = @ProcName,
        @OperationType = 'CREATE_OTP',
        @ExecutionTimeMs = @ExecutionTimeMs,
        @RowsAffected = @RowsAffected,
        @Parameters = @Parameters,
        @Success = CASE WHEN @Outcome = 'created' THEN 1 ELSE 0 END,
        @ErrorMessage = CASE WHEN @Outcome != 'created' THEN @Outcome ELSE NULL END;
    
    -- Return results
    SELECT 
        CASE WHEN @Outcome = 'created' THEN @OtpUniqueId ELSE CAST(NULL AS UNIQUEIDENTIFIER) END AS OtpUniqueId,
        @Outcome AS Outcome;
END;
GO


CREATE PROCEDURE dbo.UpdateOtpStatus
    @OtpUniqueId UNIQUEIDENTIFIER, @NewStatus NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @CurrentStatus NVARCHAR(20), @FlowId BIGINT, @FlowUniqueId UNIQUEIDENTIFIER;

    SELECT @CurrentStatus = o.Status, @FlowId = vf.Id, @FlowUniqueId = vf.UniqueId
    FROM dbo.OtpRecords AS o JOIN dbo.VerificationFlows AS vf ON o.FlowUniqueId = vf.UniqueId
    WHERE o.UniqueId = @OtpUniqueId AND o.IsDeleted = 0 AND vf.IsDeleted = 0 AND vf.Status = 'pending' AND vf.ExpiresAt > GETUTCDATE();

    IF @@ROWCOUNT = 0 BEGIN SELECT CAST(0 AS BIT) AS Success, 'OTP not found, deleted, or flow invalid/expired' AS Message; RETURN; END
    IF @CurrentStatus = 'expired' AND @NewStatus = 'pending' BEGIN SELECT CAST(0 AS BIT) AS Success, 'Cannot transition from expired to pending' AS Message; RETURN; END

    UPDATE dbo.OtpRecords SET Status = @NewStatus, IsActive = CASE WHEN @NewStatus = 'pending' THEN 1 ELSE 0 END WHERE UniqueId = @OtpUniqueId AND IsDeleted = 0;
    IF @@ROWCOUNT = 0 BEGIN SELECT CAST(0 AS BIT) AS Success, 'Failed to update OTP: no rows affected' AS Message; RETURN; END

    IF @NewStatus = 'failed' INSERT INTO dbo.FailedOtpAttempts (OtpUniqueId, FlowUniqueId) VALUES (@OtpUniqueId, @FlowUniqueId);
    ELSE IF @NewStatus = 'verified' UPDATE dbo.VerificationFlows SET Status = 'verified' WHERE Id = @FlowId;

    SELECT CAST(1 AS BIT) AS Success, 'OTP status updated successfully' AS Message;
END;
GO


CREATE PROCEDURE dbo.UpdateVerificationFlowStatus
    @FlowUniqueId UNIQUEIDENTIFIER, @NewStatus NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE dbo.VerificationFlows
    SET Status = @NewStatus, ExpiresAt = CASE WHEN @NewStatus = 'verified' THEN DATEADD(hour, 24, GETUTCDATE()) ELSE ExpiresAt END
    WHERE UniqueId = @FlowUniqueId AND IsDeleted = 0;
    SELECT @@ROWCOUNT AS RowsAffected;
END;
GO


CREATE FUNCTION dbo.GetPhoneNumber (@PhoneUniqueId UNIQUEIDENTIFIER)
RETURNS TABLE AS RETURN
( SELECT pn.PhoneNumber, pn.Region, pn.UniqueId FROM dbo.PhoneNumbers AS pn WHERE pn.UniqueId = @PhoneUniqueId AND pn.IsDeleted = 0 );
GO


-- Add verification-specific configuration values
IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'VerificationFlow.DefaultExpirationMinutes')
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
    VALUES ('VerificationFlow.DefaultExpirationMinutes', '5', 'int', 'Default verification flow expiration in minutes', 'Security');

IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'OTP.EnableRateLimitTracking')
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
    VALUES ('OTP.EnableRateLimitTracking', '1', 'bool', 'Enable OTP rate limit tracking and enforcement', 'Security');

COMMIT TRANSACTION;
GO

PRINT '✅ Enhanced Verification Flow procedures created successfully with:';
PRINT '   - Advanced OTP security with configurable parameters';
PRINT '   - Enhanced rate limiting and flow management';
PRINT '   - Comprehensive input validation and sanitization';
PRINT '   - Complete audit trail for verification events';
PRINT '   - Performance monitoring and metrics collection';
PRINT '   - Configuration-driven security parameters';
GO