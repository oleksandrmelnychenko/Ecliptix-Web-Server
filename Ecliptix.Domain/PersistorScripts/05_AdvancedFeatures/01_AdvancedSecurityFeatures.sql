/*
================================================================================
Layer 5.1: Advanced Security Features
================================================================================
Purpose: Advanced security procedures with behavioral analysis and threat detection
Dependencies: Layers 1-4 (Complete infrastructure and business logic)
Execution Order: 12th - Advanced security and threat detection layer

Features:
- Advanced login with behavioral analysis
- Threat detection and response
- Geographic anomaly detection
- Advanced rate limiting with exponential backoff
- Suspicious activity pattern recognition
- Advanced lockout mechanisms

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
PRINT 'Layer 5.1: Advanced Security Features';
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
VALUES (@DeploymentId, '01_AdvancedSecurityFeatures.sql', 11, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- CLEANUP EXISTING PROCEDURES
    -- ============================================================================
    
    PRINT 'Cleaning up existing advanced security procedures...';
    
    IF OBJECT_ID('dbo.LoginMembership', 'P') IS NOT NULL DROP PROCEDURE dbo.LoginMembership;
    IF OBJECT_ID('dbo.AnalyzeSuspiciousActivity', 'P') IS NOT NULL DROP PROCEDURE dbo.AnalyzeSuspiciousActivity;
    IF OBJECT_ID('dbo.CalculateLockoutDuration', 'P') IS NOT NULL DROP PROCEDURE dbo.CalculateLockoutDuration;
    IF OBJECT_ID('dbo.DetectGeographicAnomaly', 'P') IS NOT NULL DROP PROCEDURE dbo.DetectGeographicAnomaly;
    IF OBJECT_ID('dbo.ProcessSecurityThreat', 'P') IS NOT NULL DROP PROCEDURE dbo.ProcessSecurityThreat;
    
    PRINT '✓ Existing advanced security procedures cleaned up';
    
    -- ============================================================================
    -- SECURITY ANALYSIS PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating security analysis procedures...';
    
    -- CalculateLockoutDuration: Advanced lockout with exponential backoff
    CREATE PROCEDURE dbo.CalculateLockoutDuration
        @PhoneNumber NVARCHAR(18),
        @BaseLockoutMinutes INT,
        @LockoutDurationMinutes INT OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @LockoutMarkerPrefix NVARCHAR(20) = 'LOCKED_UNTIL:';
        DECLARE @LockoutPattern NVARCHAR(30) = @LockoutMarkerPrefix + '%';
        DECLARE @PreviousLockouts INT;
        DECLARE @MaxLockoutDuration INT = CAST(dbo.GetConfigValue('Membership.MaxLockoutDuration') AS INT);
        
        -- Count previous lockouts in the last 24 hours
        SELECT @PreviousLockouts = COUNT(*)
        FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber
          AND Outcome LIKE @LockoutPattern
          AND Timestamp > DATEADD(DAY, -1, GETUTCDATE());
        
        -- Calculate exponential backoff
        SET @LockoutDurationMinutes = @BaseLockoutMinutes * POWER(2, @PreviousLockouts);
        
        -- Cap at maximum duration
        IF @LockoutDurationMinutes > @MaxLockoutDuration
            SET @LockoutDurationMinutes = @MaxLockoutDuration;
        
        -- Log lockout calculation
        EXEC dbo.LogAuditEvent 
            @EventType = 'LOCKOUT_DURATION_CALCULATED',
            @Details = CONCAT('Lockout duration calculated: ', @LockoutDurationMinutes, ' minutes'),
            @AdditionalData = CONCAT('PhoneNumber:', dbo.MaskSensitiveData(@PhoneNumber, 'PHONE'), ', PreviousLockouts:', @PreviousLockouts);
    END;
    
    -- DetectGeographicAnomaly: Geographic-based anomaly detection
        CREATE PROCEDURE dbo.DetectGeographicAnomaly
        @PhoneNumber NVARCHAR(18),
        @CurrentIpAddress NVARCHAR(45),
        @IsAnomaly BIT OUTPUT,
        @AnomalyReason NVARCHAR(255) OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        SET @IsAnomaly = 0;
        SET @AnomalyReason = NULL;
        
        -- Skip if geographic blocking is disabled
        IF CAST(dbo.GetConfigValue('Membership.EnableGeoBlocking') AS BIT) = 0
            RETURN;
        
        DECLARE @RecentIpCount INT;
        DECLARE @SuspiciousThreshold INT = CAST(dbo.GetConfigValue('Membership.SuspiciousActivityThreshold') AS INT);
        
        -- Count unique IP addresses in the last hour
        SELECT @RecentIpCount = COUNT(DISTINCT 
            CASE 
                WHEN Outcome LIKE 'ip_changed:%' THEN SUBSTRING(Outcome, 12, LEN(Outcome))
                ELSE @CurrentIpAddress
            END
        )
        FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber
          AND Timestamp > DATEADD(HOUR, -1, GETUTCDATE());
        
        -- Detect rapid IP changes
        IF @RecentIpCount > @SuspiciousThreshold
        BEGIN
            SET @IsAnomaly = 1;
            SET @AnomalyReason = CONCAT('Multiple IP addresses detected: ', @RecentIpCount, ' in last hour');
        END
        
        -- Additional geographic checks could be added here
        -- (e.g., IP geolocation, distance calculations, etc.)
    END;
    
    -- AnalyzeSuspiciousActivity: Comprehensive threat analysis
        CREATE PROCEDURE dbo.AnalyzeSuspiciousActivity
        @PhoneNumber NVARCHAR(18),
        @IpAddress NVARCHAR(45),
        @UserAgent NVARCHAR(500),
        @SuspiciousScore INT OUTPUT,
        @ThreatDetails NVARCHAR(MAX) OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        SET @SuspiciousScore = 0;
        SET @ThreatDetails = '';
        
        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
        
        -- ================================================================
        -- RAPID ATTEMPT DETECTION
        -- ================================================================
        
        DECLARE @AttemptsInLastMinute INT;
        SELECT @AttemptsInLastMinute = COUNT(*)
        FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber
          AND Timestamp > DATEADD(MINUTE, -1, @CurrentTime);
        
        IF @AttemptsInLastMinute > 10
        BEGIN
            SET @SuspiciousScore = @SuspiciousScore + 50;
            SET @ThreatDetails = @ThreatDetails + 'Rapid fire attempts detected; ';
        END
        ELSE IF @AttemptsInLastMinute > 5
        BEGIN
            SET @SuspiciousScore = @SuspiciousScore + 20;
            SET @ThreatDetails = @ThreatDetails + 'High frequency attempts; ';
        END
        
        -- ================================================================
        -- GEOGRAPHIC ANOMALY DETECTION
        -- ================================================================
        
        DECLARE @IsGeoAnomaly BIT, @GeoAnomalyReason NVARCHAR(255);
        EXEC dbo.DetectGeographicAnomaly @PhoneNumber, @IpAddress, @IsGeoAnomaly OUTPUT, @GeoAnomalyReason OUTPUT;
        
        IF @IsGeoAnomaly = 1
        BEGIN
            SET @SuspiciousScore = @SuspiciousScore + 30;
            SET @ThreatDetails = @ThreatDetails + @GeoAnomalyReason + '; ';
        END
        
        -- ================================================================
        -- USER AGENT ANALYSIS
        -- ================================================================
        
        IF @UserAgent IS NOT NULL
        BEGIN
            -- Check for suspicious user agent patterns
            IF @UserAgent LIKE '%bot%' OR @UserAgent LIKE '%crawler%' OR @UserAgent LIKE '%script%'
            BEGIN
                SET @SuspiciousScore = @SuspiciousScore + 40;
                SET @ThreatDetails = @ThreatDetails + 'Suspicious user agent detected; ';
            END
            
            -- Check for uncommon user agents
            DECLARE @UserAgentCount INT;
            SELECT @UserAgentCount = COUNT(DISTINCT UserAgent)
            FROM dbo.LoginAttempts la
            WHERE la.PhoneNumber = @PhoneNumber
              AND la.Timestamp > DATEADD(DAY, -7, @CurrentTime)
              AND LEN(la.Outcome) > 10; -- Assuming UserAgent is stored in outcome for this analysis
            
            IF @UserAgentCount > 5
            BEGIN
                SET @SuspiciousScore = @SuspiciousScore + 15;
                SET @ThreatDetails = @ThreatDetails + 'Multiple user agents detected; ';
            END
        END
        
        -- ================================================================
        -- TEMPORAL PATTERN ANALYSIS
        -- ================================================================
        
        -- Check for unusual timing patterns (e.g., attempts at odd hours)
        DECLARE @HourOfDay INT = DATEPART(HOUR, @CurrentTime);
        
        IF @HourOfDay BETWEEN 2 AND 5 -- 2 AM to 5 AM
        BEGIN
            SET @SuspiciousScore = @SuspiciousScore + 10;
            SET @ThreatDetails = @ThreatDetails + 'Unusual timing pattern (late night); ';
        END
        
        -- ================================================================
        -- FAILURE PATTERN ANALYSIS
        -- ================================================================
        
        DECLARE @RecentFailures INT;
        SELECT @RecentFailures = COUNT(*)
        FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber
          AND IsSuccess = 0
          AND Timestamp > DATEADD(HOUR, -1, @CurrentTime);
        
        IF @RecentFailures > 15
        BEGIN
            SET @SuspiciousScore = @SuspiciousScore + 25;
            SET @ThreatDetails = @ThreatDetails + 'High failure rate detected; ';
        END
        
        -- Clean up trailing separator
        IF LEN(@ThreatDetails) > 0 AND RIGHT(@ThreatDetails, 2) = '; '
            SET @ThreatDetails = LEFT(@ThreatDetails, LEN(@ThreatDetails) - 2);
    END;
    
    -- ProcessSecurityThreat: Handle detected threats
        CREATE PROCEDURE dbo.ProcessSecurityThreat
        @PhoneNumber NVARCHAR(18),
        @ThreatLevel NVARCHAR(20), -- LOW, MEDIUM, HIGH, CRITICAL
        @ThreatDetails NVARCHAR(MAX),
        @IpAddress NVARCHAR(45) = NULL,
        @ActionTaken NVARCHAR(255) OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        SET @ActionTaken = 'No action required';
        
        -- Log the threat
        EXEC dbo.LogAuditEvent 
            @EventType = 'SECURITY_THREAT_DETECTED',
            @Details = CONCAT('Threat Level: ', @ThreatLevel, ' - ', @ThreatDetails),
            @IpAddress = @IpAddress,
            @AdditionalData = CONCAT('PhoneNumber:', dbo.MaskSensitiveData(@PhoneNumber, 'PHONE')),
            @Success = 0;
        
        -- Take action based on threat level
        IF @ThreatLevel = 'CRITICAL'
        BEGIN
            -- Immediate account lockout for 24 hours
            DECLARE @CriticalLockoutMarker NVARCHAR(MAX) = CONCAT('LOCKED_UNTIL:', CONVERT(NVARCHAR(30), DATEADD(HOUR, 24, GETUTCDATE()), 127));
            EXEC dbo.LogLoginAttempt @PhoneNumber, @CriticalLockoutMarker, 0, @IpAddress;
            SET @ActionTaken = 'Account locked for 24 hours due to critical threat';
        END
        ELSE IF @ThreatLevel = 'HIGH'
        BEGIN
            -- Extended lockout
            DECLARE @HighLockoutMarker NVARCHAR(MAX) = CONCAT('LOCKED_UNTIL:', CONVERT(NVARCHAR(30), DATEADD(HOUR, 4, GETUTCDATE()), 127));
            EXEC dbo.LogLoginAttempt @PhoneNumber, @HighLockoutMarker, 0, @IpAddress;
            SET @ActionTaken = 'Account locked for 4 hours due to high threat';
        END
        ELSE IF @ThreatLevel = 'MEDIUM'
        BEGIN
            -- Standard lockout with increased monitoring
            DECLARE @MediumLockoutMarker NVARCHAR(MAX) = CONCAT('LOCKED_UNTIL:', CONVERT(NVARCHAR(30), DATEADD(HOUR, 1, GETUTCDATE()), 127));
            EXEC dbo.LogLoginAttempt @PhoneNumber, @MediumLockoutMarker, 0, @IpAddress;
            SET @ActionTaken = 'Account locked for 1 hour with enhanced monitoring';
        END
        
        -- Additional actions could include:
        -- - IP blocking/throttling
        -- - Alert notifications
        -- - Forensic data collection
    END;
    
    PRINT '✓ Security analysis procedures created';
    
    -- ============================================================================
    -- ADVANCED LOGIN PROCEDURE
    -- ============================================================================
    
    PRINT 'Creating advanced login procedure with behavioral analysis...';
    
    -- LoginMembership: Advanced login with comprehensive security
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
        DECLARE @RowsAffected INT = 0;
        
        -- Core operation variables
        DECLARE @MembershipUniqueId UNIQUEIDENTIFIER;
        DECLARE @Status NVARCHAR(20);
        DECLARE @Outcome NVARCHAR(255);
        DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
        DECLARE @StoredSecureKey VARBINARY(MAX);
        DECLARE @CreationStatus NVARCHAR(20);
        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
        DECLARE @Success BIT = 0;
        
        -- Security analysis variables
        DECLARE @SuspiciousScore INT;
        DECLARE @ThreatDetails NVARCHAR(MAX);
        DECLARE @ThreatLevel NVARCHAR(20);
        DECLARE @SecurityActionTaken NVARCHAR(255);
        
        -- Configuration-driven security parameters
        DECLARE @LockoutDurationMinutes INT = CAST(dbo.GetConfigValue('Authentication.LockoutDurationMinutes') AS INT);
        DECLARE @MaxAttemptsBeforeLockout INT = CAST(dbo.GetConfigValue('Authentication.MaxFailedAttempts') AS INT);
        DECLARE @LockoutMarkerPrefix NVARCHAR(20) = 'LOCKED_UNTIL:';
        DECLARE @LockoutPattern NVARCHAR(30) = @LockoutMarkerPrefix + '%';
        
        -- Lockout state variables
        DECLARE @LockedUntilTs DATETIME2(7);
        DECLARE @LastLockoutInitTime DATETIME2(7);
        DECLARE @LockoutMarkerOutcome NVARCHAR(MAX);
        DECLARE @FailedAttemptsCount INT;
        
        -- Build parameters for logging (mask sensitive data)
        DECLARE @Parameters NVARCHAR(MAX) = CONCAT(
            'PhoneNumber=', dbo.MaskSensitiveData(@PhoneNumber, 'PHONE'),
            ', IpAddress=', ISNULL(@IpAddress, 'NULL'),
            ', UserAgent=', CASE WHEN @UserAgent IS NULL THEN 'NULL' ELSE '[PROVIDED]' END,
            ', SessionContext=', CASE WHEN @SessionContext IS NULL THEN 'NULL' ELSE '[PROVIDED]' END
        );

        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION AND SECURITY CHECKS
            -- ================================================================
            
            -- Validate phone number format
            IF dbo.ValidatePhoneNumber(@PhoneNumber) = 0
            BEGIN
                SET @Outcome = 'invalid_phone_number_format';
                GOTO LogFailedAttempt;
            END
            
            
            -- Validate IP address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @Outcome = 'invalid_ip_address';
                GOTO LogFailedAttempt;
            END
            
            -- Sanitize inputs
            IF LEN(@UserAgent) > 500
                SET @UserAgent = LEFT(@UserAgent, 497) + '...';
            IF LEN(@SessionContext) > 200
                SET @SessionContext = LEFT(@SessionContext, 197) + '...';
            
            -- ================================================================
            -- SUSPICIOUS ACTIVITY ANALYSIS
            -- ================================================================
            
            -- Perform comprehensive threat analysis
            EXEC dbo.AnalyzeSuspiciousActivity 
                @PhoneNumber = @PhoneNumber,
                @IpAddress = @IpAddress,
                @UserAgent = @UserAgent,
                @SuspiciousScore = @SuspiciousScore OUTPUT,
                @ThreatDetails = @ThreatDetails OUTPUT;
            
            -- Determine threat level based on suspicious score
            IF @SuspiciousScore >= 80
                SET @ThreatLevel = 'CRITICAL';
            ELSE IF @SuspiciousScore >= 60
                SET @ThreatLevel = 'HIGH';
            ELSE IF @SuspiciousScore >= 40
                SET @ThreatLevel = 'MEDIUM';
            ELSE IF @SuspiciousScore >= 20
                SET @ThreatLevel = 'LOW';
            ELSE
                SET @ThreatLevel = 'NONE';
            
            -- Process security threats before allowing login attempt
            IF @ThreatLevel IN ('HIGH', 'CRITICAL')
            BEGIN
                EXEC dbo.ProcessSecurityThreat 
                    @PhoneNumber = @PhoneNumber,
                    @ThreatLevel = @ThreatLevel,
                    @ThreatDetails = @ThreatDetails,
                    @IpAddress = @IpAddress,
                    @ActionTaken = @SecurityActionTaken OUTPUT;
                
                SET @Outcome = 'blocked_due_to_' + LOWER(@ThreatLevel) + '_threat';
                GOTO LogFailedAttempt;
            END
            
            -- ================================================================
            -- LOCKOUT AND RATE LIMITING CHECKS
            -- ================================================================
            
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
                    EXEC dbo.LogError
                        @ErrorMessage = 'Failed to parse lockout timestamp',
                        @ErrorSeverity = 'WARNING',
                        @AdditionalInfo = @LockoutMarkerOutcome;
                END CATCH

                IF @LockedUntilTs IS NOT NULL AND @CurrentTime < @LockedUntilTs
                BEGIN
                    SET @Outcome = CAST(CEILING(CAST(DATEDIFF(SECOND, @CurrentTime, @LockedUntilTs) AS DECIMAL) / 60.0) AS NVARCHAR(100));
                    
                    -- Log lockout violation attempt
                    EXEC dbo.LogAuditEvent
                        @EventType = 'LOGIN_BLOCKED_LOCKOUT',
                        @Details = 'Account locked - attempted login during lockout period',
                        @IpAddress = @IpAddress,
                        @AdditionalData = @Parameters,
                        @Success = 0;
                        
                    GOTO ReturnResult;
                END
                ELSE IF @LockedUntilTs IS NOT NULL AND @CurrentTime >= @LockedUntilTs
                BEGIN
                    -- Lockout period expired, clean up
                    DELETE FROM dbo.LoginAttempts
                    WHERE PhoneNumber = @PhoneNumber
                      AND Timestamp <= @LastLockoutInitTime
                      AND (IsSuccess = 0 OR Outcome LIKE @LockoutPattern);
                    
                    SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
                    
                    -- Log lockout expiration
                    EXEC dbo.LogAuditEvent
                        @EventType = 'LOCKOUT_EXPIRED',
                        @Details = 'Account lockout period has expired',
                        @IpAddress = @IpAddress,
                        @AdditionalData = @Parameters;
                END
            END

            -- Count recent failed attempts
            SELECT @FailedAttemptsCount = COUNT(*)
            FROM dbo.LoginAttempts
            WHERE PhoneNumber = @PhoneNumber
              AND IsSuccess = 0
              AND Timestamp > ISNULL(@LastLockoutInitTime, '1900-01-01');
            
            -- ================================================================
            -- CIRCUIT BREAKER CHECK
            -- ================================================================
            
            DECLARE @CircuitOpen BIT, @CircuitError NVARCHAR(255);
            EXEC dbo.CheckCircuitBreaker 'MembershipLogin', @CircuitOpen OUTPUT, @CircuitError OUTPUT;
            
            IF @CircuitOpen = 1
            BEGIN
                SET @Outcome = 'service_unavailable';
                GOTO LogFailedAttempt;
            END
            
            -- ================================================================
            -- AUTHENTICATION LOGIC
            -- ================================================================
            
            -- Find phone number
            SELECT @PhoneNumberId = UniqueId
            FROM dbo.PhoneNumbers
            WHERE PhoneNumber = @PhoneNumber AND IsDeleted = 0;

            IF @PhoneNumberId IS NULL
            BEGIN
                SET @Outcome = 'phone_number_not_found';
                GOTO LogFailedAttempt;
            END
            
            -- Find membership with secure key validation
            SELECT TOP 1 
                @MembershipUniqueId = UniqueId,
                @StoredSecureKey = SecureKey,
                @Status = Status,
                @CreationStatus = CreationStatus
            FROM dbo.Memberships
            WHERE PhoneNumberId = @PhoneNumberId
              AND IsDeleted = 0
              AND SecureKey IS NOT NULL
            ORDER BY CreatedAt DESC;

            IF @MembershipUniqueId IS NULL
            BEGIN
                SET @Outcome = 'membership_not_found';
                GOTO LogFailedAttempt;
            END
            
            -- Validate membership status
            IF @Status != 'active'
            BEGIN
                SET @Outcome = 'inactive_membership';
                GOTO LogFailedAttempt;
            END
            
            
            -- ================================================================
            -- SUCCESS PATH
            -- ================================================================
            
            SET @Outcome = 'success';
            SET @Success = 1;
            
            -- Clean up failed attempts on successful login
            DELETE FROM dbo.LoginAttempts
            WHERE PhoneNumber = @PhoneNumber
              AND (IsSuccess = 0 OR Outcome LIKE @LockoutPattern);
            
            SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
            
            -- Record circuit breaker success
            EXEC dbo.RecordCircuitBreakerSuccess 'MembershipLogin';
            
            -- Log successful authentication
            EXEC dbo.LogLoginAttempt @PhoneNumber, @Outcome, 1, @IpAddress, @UserAgent;
            
            -- Log audit event for successful login
            EXEC dbo.LogAuditEvent
                @EventType = 'LOGIN_SUCCESS',
                @Details = 'Member logged in successfully',
                @UserId = @MembershipUniqueId,
                @IpAddress = @IpAddress,
                @AdditionalData = @Parameters;
            
            -- Log security analysis results if noteworthy
            IF @SuspiciousScore > 0
            BEGIN
                EXEC dbo.LogAuditEvent
                    @EventType = 'LOGIN_SUCCESS_WITH_ANALYSIS',
                    @Details = CONCAT('Successful login with suspicious score: ', @SuspiciousScore),
                    @UserId = @MembershipUniqueId,
                    @IpAddress = @IpAddress,
                    @AdditionalData = @ThreatDetails;
            END
                
            GOTO ReturnResult;
            
            -- ================================================================
            -- FAILURE PATH
            -- ================================================================
            
            LogFailedAttempt:
            SET @Success = 0;
            
            -- Record circuit breaker failure for systemic issues
            IF @Outcome LIKE '%service%' OR @Outcome LIKE '%system%'
                EXEC dbo.RecordCircuitBreakerFailure 'MembershipLogin', @Outcome;
            
            -- Log the failed attempt
            EXEC dbo.LogLoginAttempt @PhoneNumber, @Outcome, 0, @IpAddress, @UserAgent;
            SET @FailedAttemptsCount = @FailedAttemptsCount + 1;
            
            -- Check if lockout threshold reached
            IF @FailedAttemptsCount >= @MaxAttemptsBeforeLockout
            BEGIN
                -- Calculate advanced lockout duration
                EXEC dbo.CalculateLockoutDuration @PhoneNumber, @LockoutDurationMinutes, @LockoutDurationMinutes OUTPUT;
                
                SET @LockedUntilTs = DATEADD(MINUTE, @LockoutDurationMinutes, @CurrentTime);
                DECLARE @NewLockoutMarker NVARCHAR(MAX) = CONCAT(@LockoutMarkerPrefix, CONVERT(NVARCHAR(30), @LockedUntilTs, 127));
                EXEC dbo.LogLoginAttempt @PhoneNumber, @NewLockoutMarker, 0, @IpAddress, @UserAgent;
                SET @Outcome = CAST(@LockoutDurationMinutes AS NVARCHAR(100));
                
                -- Log lockout event
                EXEC dbo.LogAuditEvent
                    @EventType = 'ACCOUNT_LOCKED',
                    @Details = CONCAT('Account locked for ', @LockoutDurationMinutes, ' minutes due to excessive failures'),
                    @IpAddress = @IpAddress,
                    @AdditionalData = CONCAT(@Parameters, ', FailedAttempts:', @FailedAttemptsCount),
                    @Success = 0;
            END
            
            -- Log security threat if detected
            IF @ThreatLevel != 'NONE'
            BEGIN
                EXEC dbo.LogAuditEvent
                    @EventType = 'LOGIN_FAILED_WITH_THREAT',
                    @Details = CONCAT('Login failed with ', @ThreatLevel, ' threat level'),
                    @IpAddress = @IpAddress,
                    @AdditionalData = @ThreatDetails,
                    @Success = 0;
            END

        END TRY
        BEGIN CATCH
            SET @Success = 0;
            SET @Outcome = 'system_error';
            
            -- Record circuit breaker failure
            EXEC dbo.RecordCircuitBreakerFailure 'MembershipLogin', ERROR_MESSAGE();
            
            -- Log the error
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = 'ERROR',
                @AdditionalInfo = @Parameters;
        END CATCH
        
        ReturnResult:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = 'LoginMembership',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = 'milliseconds',
            @AdditionalData = CONCAT('Success:', @Success, ', SuspiciousScore:', ISNULL(@SuspiciousScore, 0), ', RowsAffected:', @RowsAffected);
        
        -- Return results
        SELECT 
            CASE WHEN @Success = 1 THEN @MembershipUniqueId ELSE NULL END AS MembershipUniqueId,
            CASE WHEN @Success = 1 THEN @Status ELSE NULL END AS Status,
            @Outcome AS Outcome,
            CASE WHEN @Success = 1 THEN @StoredSecureKey ELSE NULL END AS SecureKey,
            ISNULL(@SuspiciousScore, 0) AS SuspiciousScore,
            @ThreatLevel AS ThreatLevel;
    END;
    
    PRINT '✓ Advanced login procedure created';
    
    -- ============================================================================
    -- PROCEDURE VALIDATION
    -- ============================================================================
    
    PRINT 'Validating advanced security procedures...';
    
    DECLARE @ProcedureCount INT;
    SELECT @ProcedureCount = COUNT(*)
    FROM sys.procedures p
    INNER JOIN sys.schemas s ON p.schema_id = s.schema_id
    WHERE s.name = 'dbo' 
    AND p.name IN (
        'CalculateLockoutDuration', 'DetectGeographicAnomaly', 'AnalyzeSuspiciousActivity',
        'ProcessSecurityThreat', 'LoginMembership'
    );
    
    IF @ProcedureCount = 5
        PRINT '✓ All 5 advanced security procedures created successfully';
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
    PRINT 'Layer 5.1: Advanced Security Features Completed Successfully';
    PRINT 'Procedures created: ' + CAST(@ProcedureCount AS NVARCHAR(10));
    PRINT 'Features: Behavioral analysis, threat detection, advanced lockout';
    PRINT 'Security: Geographic anomaly detection, suspicious activity analysis';
    PRINT 'Next: Layer 5.2 - Advanced Maintenance & Monitoring';
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
    PRINT 'ERROR in Layer 5.1: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO