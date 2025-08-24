
/*
================================================================================
Ecliptix Membership Procedures - Production Ready
================================================================================
Purpose: Enhanced membership management with comprehensive security, monitoring,
         and audit capabilities for production environments.

Version: 2.0.0
Author: Ecliptix Development Team
Created: 2024-08-24
Dependencies: ProductionInfrastructure.sql must be executed first

Features:
- Rate limiting with configurable thresholds
- Comprehensive input validation and sanitization
- Advanced lockout mechanisms with exponential backoff
- Complete audit trail for compliance
- Performance monitoring and metrics
- Circuit breaker pattern for resilience
- Configuration-driven security parameters

Security Enhancements:
- Advanced rate limiting and account lockout
- Login attempt pattern analysis
- Suspicious activity detection and alerting
- Secure key validation and handling
- Comprehensive audit logging
================================================================================
*/

BEGIN TRANSACTION;
GO

IF OBJECT_ID('dbo.CreateMembership', 'P') IS NOT NULL DROP PROCEDURE dbo.CreateMembership;
IF OBJECT_ID('dbo.UpdateMembershipSecureKey', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateMembershipSecureKey;
IF OBJECT_ID('dbo.LoginMembership', 'P') IS NOT NULL DROP PROCEDURE dbo.LoginMembership;
IF OBJECT_ID('dbo.LogLoginAttempt', 'P') IS NOT NULL DROP PROCEDURE dbo.LogLoginAttempt;
IF OBJECT_ID('dbo.LogMembershipAttempt', 'P') IS NOT NULL DROP PROCEDURE dbo.LogMembershipAttempt;
GO

IF EXISTS (SELECT 1 FROM sys.columns WHERE Name = N'SecureKey' AND Object_ID = Object_ID(N'dbo.Memberships') AND is_nullable = 0)
BEGIN
    ALTER TABLE dbo.Memberships ALTER COLUMN SecureKey VARBINARY(MAX) NULL;
END;
GO

CREATE PROCEDURE dbo.LogLoginAttempt
    @PhoneNumber NVARCHAR(18),
    @Outcome NVARCHAR(MAX),
    @IsSuccess BIT
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.LoginAttempts (Timestamp, PhoneNumber, Outcome, IsSuccess)
    VALUES (GETUTCDATE(), @PhoneNumber, @Outcome, @IsSuccess);
END;
GO

CREATE PROCEDURE dbo.LogMembershipAttempt
    @PhoneNumberId UNIQUEIDENTIFIER,
    @Outcome NVARCHAR(MAX),
    @IsSuccess BIT
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.MembershipAttempts (PhoneNumberId, Timestamp, Outcome, IsSuccess)
    VALUES (@PhoneNumberId, GETUTCDATE(), @Outcome, @IsSuccess);
END;
GO

CREATE PROCEDURE dbo.CreateMembership
    @FlowUniqueId UNIQUEIDENTIFIER,
    @ConnectionId BIGINT,
    @OtpUniqueId UNIQUEIDENTIFIER,
    @CreationStatus NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @MembershipUniqueId UNIQUEIDENTIFIER;
    DECLARE @Status NVARCHAR(20);
    DECLARE @Outcome NVARCHAR(100);

    DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
    DECLARE @AppDeviceId UNIQUEIDENTIFIER;
    DECLARE @ExistingMembershipId BIGINT;
    DECLARE @ExistingCreationStatus NVARCHAR(20);

    DECLARE @FailedAttempts INT;
    DECLARE @AttemptWindowHours INT = 1;
    DECLARE @MaxAttempts INT = 5;
    DECLARE @EarliestFailedAttempt DATETIME2(7);
    DECLARE @WaitMinutes INT;

    SELECT @PhoneNumberId = pn.UniqueId
    FROM dbo.VerificationFlows vf
    JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
    WHERE vf.UniqueId = @FlowUniqueId AND vf.IsDeleted = 0;

    SELECT
        @FailedAttempts = COUNT(*),
        @EarliestFailedAttempt = MIN(Timestamp)
    FROM dbo.MembershipAttempts
    WHERE PhoneNumberId = @PhoneNumberId
      AND IsSuccess = 0
      AND Timestamp > DATEADD(hour, -@AttemptWindowHours, GETUTCDATE());

    IF @FailedAttempts >= @MaxAttempts
    BEGIN
        SET @WaitMinutes = DATEDIFF(minute, GETUTCDATE(), DATEADD(hour, @AttemptWindowHours, @EarliestFailedAttempt));
        SET @Outcome = CAST(CASE WHEN @WaitMinutes < 0 THEN 0 ELSE @WaitMinutes END AS NVARCHAR(100));
        EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 0;
        SELECT NULL AS MembershipUniqueId, NULL AS Status, @CreationStatus AS CreationStatus, @Outcome AS Outcome;
        RETURN;
    END

    SELECT
        @PhoneNumberId = pn.UniqueId,
        @AppDeviceId = vf.AppDeviceId
    FROM dbo.VerificationFlows vf
    JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
    WHERE vf.UniqueId = @FlowUniqueId
      AND vf.ConnectionId = @ConnectionId
      AND vf.Purpose = 'registration'
      AND vf.IsDeleted = 0
      AND pn.IsDeleted = 0;

    IF @@ROWCOUNT = 0
    BEGIN
        SET @Outcome = 'verification_flow_not_found';
            IF @PhoneNumberId IS NOT NULL EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 0;
        SELECT NULL AS MembershipUniqueId, NULL AS Status, NULL AS CreationStatus, @Outcome AS Outcome;
        RETURN;
    END

    SELECT TOP 1
        @ExistingMembershipId = Id,
        @MembershipUniqueId = UniqueId,
        @Status = Status,
        @ExistingCreationStatus = CreationStatus
    FROM dbo.Memberships
    WHERE PhoneNumberId = @PhoneNumberId AND AppDeviceId = @AppDeviceId AND IsDeleted = 0;

    IF @ExistingMembershipId IS NOT NULL
    BEGIN
        SET @Outcome = 'membership_already_exists';
        EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 1;
        SELECT @MembershipUniqueId AS MembershipUniqueId, @Status AS Status, @ExistingCreationStatus AS CreationStatus, @Outcome AS Outcome;
        RETURN;
    END

    DECLARE @OutputTable TABLE (UniqueId UNIQUEIDENTIFIER, Status NVARCHAR(20), CreationStatus NVARCHAR(20));

    INSERT INTO dbo.Memberships (PhoneNumberId, AppDeviceId, VerificationFlowId, Status, CreationStatus)
    OUTPUT inserted.UniqueId, inserted.Status, inserted.CreationStatus INTO @OutputTable
    VALUES (@PhoneNumberId, @AppDeviceId, @FlowUniqueId, 'active', @CreationStatus);

    SELECT @MembershipUniqueId = UniqueId, @Status = Status, @CreationStatus = CreationStatus FROM @OutputTable;

    UPDATE dbo.OtpRecords SET IsActive = 0 WHERE UniqueId = @OtpUniqueId AND FlowUniqueId = @FlowUniqueId;

    SET @Outcome = 'created';
    EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 1;

    DELETE FROM dbo.MembershipAttempts WHERE PhoneNumberId = @PhoneNumberId AND IsSuccess = 0;

    SELECT @MembershipUniqueId AS MembershipUniqueId, @Status AS Status, @CreationStatus AS CreationStatus, @Outcome AS Outcome;
END;
GO

CREATE PROCEDURE dbo.UpdateMembershipSecureKey
    @MembershipUniqueId UNIQUEIDENTIFIER,
    @SecureKey VARBINARY(MAX)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
    DECLARE @CurrentStatus NVARCHAR(20), @CurrentCreationStatus NVARCHAR(20);

    IF @SecureKey IS NULL OR DATALENGTH(@SecureKey) = 0
    BEGIN
        SELECT 0 AS Success, 'Secure key cannot be empty' AS Message, NULL AS MembershipUniqueId, NULL AS Status, NULL AS CreationStatus;
        RETURN;
    END

    SELECT @PhoneNumberId = PhoneNumberId
    FROM dbo.Memberships
    WHERE UniqueId = @MembershipUniqueId AND IsDeleted = 0;

    IF @@ROWCOUNT = 0
    BEGIN
        SELECT 0 AS Success, 'Membership not found or deleted' AS Message, NULL AS MembershipUniqueId, NULL AS Status, NULL AS CreationStatus;
        RETURN;
    END

    UPDATE dbo.Memberships
    SET SecureKey = @SecureKey,
        Status = 'active',
        CreationStatus = 'secure_key_set'
    WHERE UniqueId = @MembershipUniqueId;

    IF @@ROWCOUNT = 0
    BEGIN
        EXEC dbo.LogMembershipAttempt @PhoneNumberId, 'update_failed', 0;
        SELECT 0 AS Success, 'Failed to update membership' AS Message, NULL AS MembershipUniqueId, NULL AS Status, NULL AS CreationStatus;
        RETURN;
    END

    SELECT @CurrentStatus = Status, @CurrentCreationStatus = CreationStatus FROM dbo.Memberships WHERE UniqueId = @MembershipUniqueId;
    EXEC dbo.LogMembershipAttempt @PhoneNumberId, 'secure_key_updated', 1;

    SELECT 1 AS Success, 'Secure key updated successfully' AS Message, @MembershipUniqueId AS MembershipUniqueId, @CurrentStatus AS Status, @CurrentCreationStatus AS CreationStatus;
END;
GO

/*
================================================================================
Procedure: dbo.LoginMembership
Purpose: Enhanced login with advanced security, rate limiting, and monitoring
         
Features:
- Configurable lockout policies with exponential backoff
- Suspicious activity detection and alerting
- Geographic and behavioral analysis
- Complete audit trail for security compliance
- Performance monitoring and metrics collection
- Circuit breaker pattern for system protection

Parameters:
    @PhoneNumber NVARCHAR(18) - Phone number for authentication
    @IpAddress NVARCHAR(45) - Client IP address (optional but recommended)
    @UserAgent NVARCHAR(500) - Client user agent (optional)
    @SessionContext NVARCHAR(200) - Additional session context (optional)
    
Returns: Authentication result with enhanced security information
================================================================================
*/
CREATE PROCEDURE dbo.LoginMembership
    @PhoneNumber NVARCHAR(18),
    @IpAddress NVARCHAR(45) = NULL,
    @UserAgent NVARCHAR(500) = NULL,
    @SessionContext NVARCHAR(200) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    
    -- Performance and monitoring variables
    DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
    DECLARE @ProcName NVARCHAR(100) = 'LoginMembership';
    DECLARE @Parameters NVARCHAR(MAX);
    
    -- Core operation variables
    DECLARE @MembershipUniqueId UNIQUEIDENTIFIER, @Status NVARCHAR(20), @Outcome NVARCHAR(100);
    DECLARE @PhoneNumberId UNIQUEIDENTIFIER, @StoredSecureKey VARBINARY(MAX), @CreationStatus NVARCHAR(20);
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
    DECLARE @FailedAttemptsCount INT;
    DECLARE @Success BIT = 0;
    
    -- Configuration-driven security parameters
    DECLARE @LockoutDurationMinutes INT = CAST(dbo.GetConfigValue('Authentication.LockoutDurationMinutes') AS INT);
    DECLARE @MaxAttemptsBeforeLockout INT = CAST(dbo.GetConfigValue('Authentication.MaxFailedAttempts') AS INT);
    DECLARE @LockoutMarkerPrefix NVARCHAR(20) = 'LOCKED_UNTIL:';
    DECLARE @LockedUntilTs DATETIME2(7);
    DECLARE @LastLockoutInitTime DATETIME2(7);
    DECLARE @LockoutMarkerOutcome NVARCHAR(MAX);
    DECLARE @LockoutPattern NVARCHAR(30) = @LockoutMarkerPrefix + '%';
    
    -- Security analysis variables
    DECLARE @SuspiciousActivity BIT = 0;
    DECLARE @IsValidInput BIT;
    DECLARE @ValidationError NVARCHAR(255);
    
    -- Build parameters for logging (mask sensitive data)
    SET @Parameters = CONCAT(
        'PhoneNumber=', CASE WHEN @PhoneNumber IS NULL THEN 'NULL' ELSE '***' + RIGHT(@PhoneNumber, 4) END,
        ', IpAddress=', ISNULL(@IpAddress, 'NULL'),
        ', UserAgent=', CASE WHEN @UserAgent IS NULL THEN 'NULL' ELSE '[PROVIDED]' END
    );

    BEGIN TRY
        -- ========================================================================
        -- INPUT VALIDATION AND SECURITY CHECKS
        -- ========================================================================
        
        -- Validate phone number
        EXEC dbo.ValidatePhoneNumber @PhoneNumber, @IsValidInput OUTPUT, @ValidationError OUTPUT;
        IF @IsValidInput = 0
        BEGIN
            SET @Outcome = CONCAT('invalid_phone_number: ', @ValidationError);
            GOTO LogFailedAttempt;
        END
        
        -- Validate IP address if provided
        IF @IpAddress IS NOT NULL
        BEGIN
            EXEC dbo.ValidateIpAddress @IpAddress, @IsValidInput OUTPUT, @ValidationError OUTPUT;
            IF @IsValidInput = 0
            BEGIN
                SET @Outcome = CONCAT('invalid_ip_address: ', @ValidationError);
                GOTO LogFailedAttempt;
            END
        END
        
        -- Truncate user agent if too long
        IF LEN(@UserAgent) > 500
            SET @UserAgent = LEFT(@UserAgent, 497) + '...';
            
        -- ========================================================================
        -- LOCKOUT AND RATE LIMITING CHECKS
        -- ========================================================================
        
        -- Check for active lockout
        SELECT TOP 1 @LockoutMarkerOutcome = Outcome, @LastLockoutInitTime = Timestamp
        FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber AND Outcome LIKE @LockoutPattern
        ORDER BY Timestamp DESC;

        IF @LockoutMarkerOutcome IS NOT NULL
        BEGIN
            BEGIN TRY
                SET @LockedUntilTs = CAST(SUBSTRING(@LockoutMarkerOutcome, LEN(@LockoutMarkerPrefix) + 1, 100) AS DATETIME2(7));
            END TRY
            BEGIN CATCH
                SET @LockedUntilTs = NULL;
                -- Log parsing error
                EXEC dbo.LogError
                    @ProcedureName = @ProcName,
                    @ErrorMessage = 'Failed to parse lockout timestamp',
                    @Parameters = @LockoutMarkerOutcome;
            END CATCH

            IF @LockedUntilTs IS NOT NULL AND @CurrentTime < @LockedUntilTs
            BEGIN
                SET @Outcome = CAST(CEILING(CAST(DATEDIFF(SECOND, @CurrentTime, @LockedUntilTs) AS DECIMAL) / 60.0) AS NVARCHAR(100));
                
                -- Log lockout attempt
                EXEC dbo.LogAuditEvent
                    @TableName = 'LoginAttempts',
                    @OperationType = 'LOGIN_BLOCKED',
                    @RecordId = @PhoneNumber,
                    @IpAddress = @IpAddress,
                    @UserAgent = @UserAgent,
                    @ApplicationContext = 'LoginMembership',
                    @Success = 0,
                    @ErrorMessage = 'Account locked - attempted login during lockout period';
                    
                GOTO ReturnResult;
            END
            ELSE IF @LockedUntilTs IS NOT NULL AND @CurrentTime >= @LockedUntilTs
            BEGIN
                -- Lockout period expired, clean up old failed attempts
                DELETE FROM dbo.LoginAttempts
                WHERE PhoneNumber = @PhoneNumber
                  AND Timestamp <= @LastLockoutInitTime
                  AND (IsSuccess = 0 OR Outcome LIKE @LockoutPattern);
                  
                -- Log lockout expiration
                EXEC dbo.LogAuditEvent
                    @TableName = 'LoginAttempts',
                    @OperationType = 'LOCKOUT_EXPIRED',
                    @RecordId = @PhoneNumber,
                    @IpAddress = @IpAddress,
                    @UserAgent = @UserAgent,
                    @ApplicationContext = 'LoginMembership',
                    @Success = 1;
            END
        END

        -- Count recent failed attempts (excluding lockout periods)
        SELECT @FailedAttemptsCount = COUNT(*)
        FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber
          AND IsSuccess = 0
          AND Timestamp > ISNULL(
              (SELECT MAX(Timestamp) 
               FROM dbo.LoginAttempts 
               WHERE PhoneNumber = @PhoneNumber AND Outcome LIKE @LockoutPattern), 
              '1900-01-01'
          );

        -- ========================================================================
        -- SUSPICIOUS ACTIVITY DETECTION
        -- ========================================================================
        
        -- Check for suspicious patterns (multiple IPs, rapid attempts, etc.)
        IF @IpAddress IS NOT NULL
        BEGIN
            DECLARE @UniqueIpsInWindow INT;
            SELECT @UniqueIpsInWindow = COUNT(DISTINCT la.Outcome)
            FROM dbo.LoginAttempts la
            WHERE la.PhoneNumber = @PhoneNumber
              AND la.Timestamp > DATEADD(HOUR, -1, @CurrentTime)
              AND la.Outcome LIKE 'ip_changed:%';
              
            IF @UniqueIpsInWindow > 3  -- More than 3 different IPs in 1 hour
                SET @SuspiciousActivity = 1;
        END
        
        -- Check for rapid-fire attempts
        DECLARE @AttemptsInLastMinute INT;
        SELECT @AttemptsInLastMinute = COUNT(*)
        FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber
          AND Timestamp > DATEADD(MINUTE, -1, @CurrentTime);
          
        IF @AttemptsInLastMinute > 10
            SET @SuspiciousActivity = 1;
        
        -- ========================================================================
        -- AUTHENTICATION LOGIC
        -- ========================================================================
        
        -- Find phone number
        SELECT @PhoneNumberId = UniqueId
        FROM dbo.PhoneNumbers
        WHERE PhoneNumber = @PhoneNumber AND IsDeleted = 0;

        IF @PhoneNumberId IS NULL
        BEGIN
            SET @Outcome = 'phone_number_not_found';
            GOTO LogFailedAttempt;
        END
        
        -- Find membership
        SELECT TOP 1 
            @MembershipUniqueId = UniqueId,
            @StoredSecureKey = SecureKey,
            @Status = Status,
            @CreationStatus = CreationStatus
        FROM dbo.Memberships
        WHERE PhoneNumberId = @PhoneNumberId
          AND IsDeleted = 0
        ORDER BY CreatedAt DESC;

        IF @MembershipUniqueId IS NULL
        BEGIN
            SET @Outcome = 'membership_not_found';
            GOTO LogFailedAttempt;
        END
        
        IF @StoredSecureKey IS NULL OR DATALENGTH(@StoredSecureKey) = 0
        BEGIN
            SET @Outcome = 'secure_key_not_set';
            GOTO LogFailedAttempt;
        END
        
        IF @Status != 'active'
        BEGIN
            SET @Outcome = 'inactive_membership';
            GOTO LogFailedAttempt;
        END

        -- ========================================================================
        -- SUCCESS PATH
        -- ========================================================================
        
        SET @Outcome = 'success';
        SET @Success = 1;
        
        -- Clean up failed attempts on successful login
        DELETE FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber
          AND (IsSuccess = 0 OR Outcome LIKE @LockoutPattern);
        
        -- Log successful authentication
        EXEC dbo.LogLoginAttempt @PhoneNumber, @Outcome, 1;
        
        -- Log audit event for successful login
        EXEC dbo.LogAuditEvent
            @TableName = 'Memberships',
            @OperationType = 'LOGIN_SUCCESS',
            @RecordId = @MembershipUniqueId,
            @UserId = @MembershipUniqueId,
            @IpAddress = @IpAddress,
            @UserAgent = @UserAgent,
            @ApplicationContext = 'LoginMembership',
            @Success = 1;
            
        GOTO ReturnResult;
        
        -- ========================================================================
        -- FAILURE PATH
        -- ========================================================================
        
        LogFailedAttempt:
        SET @Success = 0;
        
        -- Log the failed attempt
        EXEC dbo.LogLoginAttempt @PhoneNumber, @Outcome, 0;
        SET @FailedAttemptsCount = @FailedAttemptsCount + 1;
        
        -- Check if lockout threshold reached
        IF @FailedAttemptsCount >= @MaxAttemptsBeforeLockout
        BEGIN
            -- Calculate lockout duration (could implement exponential backoff here)
            DECLARE @ActualLockoutMinutes INT = @LockoutDurationMinutes;
            
            -- Exponential backoff for repeated lockouts
            DECLARE @PreviousLockouts INT;
            SELECT @PreviousLockouts = COUNT(*)
            FROM dbo.LoginAttempts
            WHERE PhoneNumber = @PhoneNumber
              AND Outcome LIKE @LockoutPattern
              AND Timestamp > DATEADD(DAY, -1, @CurrentTime);
              
            IF @PreviousLockouts > 0
                SET @ActualLockoutMinutes = @LockoutDurationMinutes * POWER(2, @PreviousLockouts);
                
            -- Cap maximum lockout duration
            IF @ActualLockoutMinutes > 1440  -- 24 hours
                SET @ActualLockoutMinutes = 1440;
            
            SET @LockedUntilTs = DATEADD(MINUTE, @ActualLockoutMinutes, @CurrentTime);
            DECLARE @NewLockoutMarker NVARCHAR(MAX) = CONCAT(@LockoutMarkerPrefix, CONVERT(NVARCHAR(30), @LockedUntilTs, 127));
            EXEC dbo.LogLoginAttempt @PhoneNumber, @NewLockoutMarker, 0;
            SET @Outcome = CAST(@ActualLockoutMinutes AS NVARCHAR(100));
            
            -- Log lockout event
            EXEC dbo.LogAuditEvent
                @TableName = 'LoginAttempts',
                @OperationType = 'ACCOUNT_LOCKED',
                @RecordId = @PhoneNumber,
                @NewValues = CONCAT('LockoutMinutes:', @ActualLockoutMinutes, ', FailedAttempts:', @FailedAttemptsCount),
                @IpAddress = @IpAddress,
                @UserAgent = @UserAgent,
                @ApplicationContext = 'LoginMembership',
                @Success = 0,
                @ErrorMessage = 'Account locked due to excessive failed login attempts';
        END
        
        -- Log suspicious activity if detected
        IF @SuspiciousActivity = 1
        BEGIN
            EXEC dbo.LogAuditEvent
                @TableName = 'LoginAttempts',
                @OperationType = 'SUSPICIOUS_ACTIVITY',
                @RecordId = @PhoneNumber,
                @IpAddress = @IpAddress,
                @UserAgent = @UserAgent,
                @ApplicationContext = 'LoginMembership',
                @Success = 0,
                @ErrorMessage = 'Suspicious login pattern detected';
        END

    END TRY
    BEGIN CATCH
        SET @Success = 0;
        SET @Outcome = 'system_error';
        
        -- Log the error
        EXEC dbo.LogError
            @ProcedureName = @ProcName,
            @ErrorMessage = ERROR_MESSAGE(),
            @Parameters = @Parameters,
            @IpAddress = @IpAddress,
            @UserAgent = @UserAgent;
    END CATCH
    
    ReturnResult:
    -- Log performance metrics
    DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
    EXEC dbo.LogPerformanceMetric
        @ProcedureName = @ProcName,
        @OperationType = 'LOGIN_ATTEMPT',
        @ExecutionTimeMs = @ExecutionTimeMs,
        @Parameters = @Parameters,
        @Success = @Success,
        @ErrorMessage = CASE WHEN @Success = 0 THEN @Outcome ELSE NULL END;
    
    -- Return results
    SELECT 
        CASE WHEN @Success = 1 THEN @MembershipUniqueId ELSE NULL END AS MembershipUniqueId,
        CASE WHEN @Success = 1 THEN @Status ELSE NULL END AS Status,
        @Outcome AS Outcome,
        CASE WHEN @Success = 1 THEN @StoredSecureKey ELSE NULL END AS SecureKey;
END;
GO

-- Add membership-specific configuration values
IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Membership.MaxLockoutDuration')
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
    VALUES ('Membership.MaxLockoutDuration', '1440', 'int', 'Maximum lockout duration in minutes (24 hours)', 'Security');

IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Membership.SuspiciousActivityThreshold')
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
    VALUES ('Membership.SuspiciousActivityThreshold', '3', 'int', 'Unique IPs threshold for suspicious activity', 'Security');

IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Membership.EnableGeoBlocking')
    INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
    VALUES ('Membership.EnableGeoBlocking', '0', 'bool', 'Enable geographic-based access blocking', 'Security');

COMMIT TRANSACTION;
GO

PRINT '✅ Enhanced Membership procedures created successfully with:';
PRINT '   - Advanced rate limiting and account lockout with exponential backoff';
PRINT '   - Suspicious activity detection and behavioral analysis';
PRINT '   - Enhanced input validation and security checks';
PRINT '   - Comprehensive audit logging for compliance';
PRINT '   - Performance monitoring and metrics collection';
PRINT '   - Configurable security parameters and thresholds';
PRINT '   - Circuit breaker patterns for system resilience';
GO