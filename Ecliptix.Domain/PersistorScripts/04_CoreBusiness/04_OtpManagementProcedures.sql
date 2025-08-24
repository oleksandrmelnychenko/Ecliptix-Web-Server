/*
================================================================================
Layer 4.4: OTP Management Procedures
================================================================================
Purpose: Complete OTP lifecycle management procedures with enhanced security
Dependencies: Layers 1-3 (Infrastructure, Domain Tables, Constraints), Layer 4.1-4.3 (Core Business)
Execution Order: 11th - OTP-specific business logic layer

Features:
- OTP record creation and management
- OTP status transitions with validation
- Verification flow status management
- Enhanced security validation
- Complete audit trail
- Performance monitoring

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
PRINT 'Layer 4.4: OTP Management Procedures';
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
VALUES (@DeploymentId, '04_OtpManagementProcedures.sql', 10, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- CLEANUP EXISTING PROCEDURES
    -- ============================================================================
    
    PRINT 'Cleaning up existing OTP management procedures...';
    
    IF OBJECT_ID('dbo.InsertOtpRecord', 'P') IS NOT NULL DROP PROCEDURE dbo.InsertOtpRecord;
    IF OBJECT_ID('dbo.UpdateOtpStatus', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateOtpStatus;
    IF OBJECT_ID('dbo.UpdateVerificationFlowStatus', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateVerificationFlowStatus;
    IF OBJECT_ID('dbo.ValidateOtpTransition', 'P') IS NOT NULL DROP PROCEDURE dbo.ValidateOtpTransition;
    IF OBJECT_ID('dbo.ProcessFailedOtpAttempt', 'P') IS NOT NULL DROP PROCEDURE dbo.ProcessFailedOtpAttempt;
    
    PRINT '✓ Existing OTP management procedures cleaned up';
    
    -- ============================================================================
    -- OTP VALIDATION PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating OTP validation procedures...';
    
    -- ValidateOtpTransition: Validate OTP status transitions
    EXEC ('
    CREATE PROCEDURE dbo.ValidateOtpTransition
        @CurrentStatus NVARCHAR(20),
        @NewStatus NVARCHAR(20),
        @IsValidTransition BIT OUTPUT,
        @ErrorMessage NVARCHAR(255) OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        SET @IsValidTransition = 0;
        SET @ErrorMessage = NULL;
        
        -- Validate status values
        IF @CurrentStatus NOT IN (''pending'', ''verified'', ''expired'', ''failed'')
        BEGIN
            SET @ErrorMessage = ''Invalid current OTP status'';
            RETURN;
        END
        
        IF @NewStatus NOT IN (''pending'', ''verified'', ''expired'', ''failed'')
        BEGIN
            SET @ErrorMessage = ''Invalid new OTP status'';
            RETURN;
        END
        
        -- Define valid transitions
        IF @CurrentStatus = ''pending''
        BEGIN
            -- Pending can transition to verified, expired, or failed
            IF @NewStatus IN (''verified'', ''expired'', ''failed'')
                SET @IsValidTransition = 1;
            ELSE
                SET @ErrorMessage = ''Invalid transition: pending can only change to verified, expired, or failed'';
        END
        ELSE IF @CurrentStatus = ''verified''
        BEGIN
            -- Verified can only transition to expired (security consideration)
            IF @NewStatus = ''expired''
                SET @IsValidTransition = 1;
            ELSE
                SET @ErrorMessage = ''Invalid transition: verified OTP can only be expired'';
        END
        ELSE IF @CurrentStatus = ''expired''
        BEGIN
            -- Expired is a terminal state - no transitions allowed
            SET @ErrorMessage = ''Invalid transition: expired OTP cannot change status'';
        END
        ELSE IF @CurrentStatus = ''failed''
        BEGIN
            -- Failed is a terminal state - no transitions allowed
            SET @ErrorMessage = ''Invalid transition: failed OTP cannot change status'';
        END
        
        -- Check for no-op transitions
        IF @CurrentStatus = @NewStatus
        BEGIN
            SET @IsValidTransition = 1;
            SET @ErrorMessage = ''No status change required'';
        END
    END;
    ');
    
    PRINT '✓ ValidateOtpTransition procedure created';
    
    -- ============================================================================
    -- OTP RECORD CREATION
    -- ============================================================================
    
    PRINT 'Creating OTP record creation procedures...';
    
    -- InsertOtpRecord: Enhanced OTP creation with comprehensive validation
    EXEC ('
    CREATE PROCEDURE dbo.InsertOtpRecord
        @FlowUniqueId UNIQUEIDENTIFIER, 
        @OtpHash NVARCHAR(255), 
        @OtpSalt NVARCHAR(255), 
        @ExpiresAt DATETIME2(7), 
        @Status NVARCHAR(20),
        @IpAddress NVARCHAR(45) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        SET XACT_ABORT ON;
        
        -- Performance monitoring
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @ProcName NVARCHAR(100) = ''InsertOtpRecord'';
        
        DECLARE @FlowId BIGINT, @PhoneNumberId BIGINT, @OtpCount SMALLINT;
        DECLARE @OtpUniqueId UNIQUEIDENTIFIER;
        DECLARE @Outcome NVARCHAR(50);
        DECLARE @RowsAffected INT = 0;
        
        -- Configuration-driven parameters
        DECLARE @MaxOtpAttempts INT = CAST(dbo.GetConfigValue(''OTP.MaxAttempts'') AS INT);
        DECLARE @MaxOtpExpirationMinutes INT = CAST(dbo.GetConfigValue(''OTP.ExpirationMinutes'') AS INT);
        
        -- Build parameters for logging (mask sensitive data)
        DECLARE @Parameters NVARCHAR(MAX) = CONCAT(
            ''FlowUniqueId='', @FlowUniqueId,
            '', Status='', ISNULL(@Status, ''NULL''),
            '', ExpiresAt='', FORMAT(@ExpiresAt, ''yyyy-MM-dd HH:mm:ss''),
            '', MaxAttempts='', @MaxOtpAttempts
        );

        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate FlowUniqueId
            IF dbo.ValidateGuid(CAST(@FlowUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Outcome = ''invalid_flow_id'';
                GOTO LogAndReturn;
            END
            
            -- Validate OTP hash and salt formats and lengths
            IF @OtpHash IS NULL OR LEN(@OtpHash) = 0
            BEGIN
                SET @Outcome = ''invalid_otp_hash'';
                EXEC dbo.LogError 
                    @ErrorMessage = ''OTP hash cannot be null or empty'', 
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            IF LEN(@OtpHash) < 32 OR LEN(@OtpHash) > 255
            BEGIN
                SET @Outcome = ''invalid_otp_hash_length'';
                EXEC dbo.LogError 
                    @ErrorMessage = ''OTP hash length must be between 32 and 255 characters'',
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            IF @OtpSalt IS NULL OR LEN(@OtpSalt) = 0
            BEGIN
                SET @Outcome = ''invalid_otp_salt'';
                EXEC dbo.LogError 
                    @ErrorMessage = ''OTP salt cannot be null or empty'',
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            IF LEN(@OtpSalt) < 16 OR LEN(@OtpSalt) > 255
            BEGIN
                SET @Outcome = ''invalid_otp_salt_length'';
                EXEC dbo.LogError 
                    @ErrorMessage = ''OTP salt length must be between 16 and 255 characters'',
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            -- Validate hash and salt are hexadecimal
            IF @OtpHash LIKE ''%[^0-9a-fA-F]%''
            BEGIN
                SET @Outcome = ''invalid_otp_hash_format'';
                EXEC dbo.LogError 
                    @ErrorMessage = ''OTP hash must contain only hexadecimal characters'',
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            IF @OtpSalt LIKE ''%[^0-9a-fA-F]%''
            BEGIN
                SET @Outcome = ''invalid_otp_salt_format'';
                EXEC dbo.LogError 
                    @ErrorMessage = ''OTP salt must contain only hexadecimal characters'',
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            -- Validate expiration time
            IF @ExpiresAt IS NULL OR @ExpiresAt <= GETUTCDATE()
            BEGIN
                SET @Outcome = ''invalid_expiration_time'';
                EXEC dbo.LogError 
                    @ErrorMessage = ''OTP expiration time must be in the future'',
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            -- Validate maximum OTP expiration
            IF @ExpiresAt > DATEADD(MINUTE, @MaxOtpExpirationMinutes, GETUTCDATE())
            BEGIN
                SET @Outcome = ''excessive_expiration_time'';
                EXEC dbo.LogError 
                    @ErrorMessage = ''OTP expiration exceeds maximum allowed duration'',
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            -- Validate status using transition validation
            DECLARE @IsValidTransition BIT, @TransitionError NVARCHAR(255);
            EXEC dbo.ValidateOtpTransition ''pending'', @Status, @IsValidTransition OUTPUT, @TransitionError OUTPUT;
            
            IF @IsValidTransition = 0 AND @TransitionError != ''No status change required''
            BEGIN
                SET @Outcome = ''invalid_initial_status'';
                EXEC dbo.LogError 
                    @ErrorMessage = @TransitionError,
                    @ErrorSeverity = ''WARNING'',
                    @AdditionalInfo = @Parameters;
                GOTO LogAndReturn;
            END
            
            -- Validate IP address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @Outcome = ''invalid_ip_address'';
                GOTO LogAndReturn;
            END
            
            -- ================================================================
            -- VERIFICATION FLOW VALIDATION
            -- ================================================================
            
            -- Get and validate verification flow
            SELECT @FlowId = Id, @PhoneNumberId = PhoneNumberId, @OtpCount = OtpCount
            FROM dbo.VerificationFlows
            WHERE UniqueId = @FlowUniqueId 
              AND Status = ''pending'' 
              AND IsDeleted = 0 
              AND ExpiresAt > GETUTCDATE();

            IF @FlowId IS NULL
            BEGIN
                SET @Outcome = ''flow_not_found_or_invalid'';
                
                -- Log potential security issue
                EXEC dbo.LogAuditEvent
                    @EventType = ''OTP_CREATION_INVALID_FLOW'',
                    @Details = ''Attempted OTP creation for invalid/expired flow'',
                    @IpAddress = @IpAddress,
                    @AdditionalData = CAST(@FlowUniqueId AS NVARCHAR(36)),
                    @Success = 0;
                
                GOTO LogAndReturn;
            END

            -- Check if maximum OTP attempts reached
            IF @OtpCount >= @MaxOtpAttempts
            BEGIN
                -- Mark flow as failed due to excessive attempts
                UPDATE dbo.VerificationFlows 
                SET Status = ''failed'', UpdatedAt = GETUTCDATE() 
                WHERE Id = @FlowId;
                
                SET @RowsAffected = @@ROWCOUNT;
                SET @Outcome = ''max_otp_attempts_reached'';
                
                -- Log security event
                EXEC dbo.LogAuditEvent
                    @EventType = ''MAX_OTP_ATTEMPTS_REACHED'',
                    @Details = ''Verification flow failed due to excessive OTP attempts'',
                    @IpAddress = @IpAddress,
                    @AdditionalData = CONCAT(''FlowId:'', @FlowUniqueId, '', OtpCount:'', @OtpCount, '', MaxAttempts:'', @MaxOtpAttempts),
                    @Success = 0;
                
                GOTO LogAndReturn;
            END
            
            -- ================================================================
            -- CIRCUIT BREAKER CHECK
            -- ================================================================
            
            DECLARE @CircuitOpen BIT, @CircuitError NVARCHAR(255);
            EXEC dbo.CheckCircuitBreaker ''OtpCreate'', @CircuitOpen OUTPUT, @CircuitError OUTPUT;
            
            IF @CircuitOpen = 1
            BEGIN
                SET @Outcome = @CircuitError;
                GOTO LogAndReturn;
            END

            -- ================================================================
            -- OTP RECORD CREATION
            -- ================================================================
            
            -- Deactivate any existing active OTPs for this flow
            UPDATE dbo.OtpRecords 
            SET IsActive = 0, Status = ''expired'', UpdatedAt = GETUTCDATE()
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
            
            -- Record circuit breaker success
            EXEC dbo.RecordCircuitBreakerSuccess ''OtpCreate'';
            
            SET @Outcome = ''created'';
            
            -- Log successful OTP creation
            EXEC dbo.LogAuditEvent
                @EventType = ''OTP_CREATED'',
                @Details = ''New OTP record created successfully'',
                @IpAddress = @IpAddress,
                @AdditionalData = CONCAT(''FlowUniqueId:'', @FlowUniqueId, '', Status:'', @Status, '', OtpCount:'', (@OtpCount + 1));

        END TRY
        BEGIN CATCH
            SET @Outcome = ''system_error'';
            
            -- Record circuit breaker failure
            EXEC dbo.RecordCircuitBreakerFailure ''OtpCreate'', ERROR_MESSAGE();
            
            -- Log the error
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = @Parameters;
        END CATCH
        
        LogAndReturn:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = ''InsertOtpRecord'',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = ''milliseconds'',
            @AdditionalData = CONCAT(''Outcome:'', @Outcome, '', RowsAffected:'', @RowsAffected);
        
        -- Return results
        SELECT 
            CASE WHEN @Outcome = ''created'' THEN @OtpUniqueId ELSE NULL END AS OtpUniqueId,
            @Outcome AS Outcome;
    END;
    ');
    
    PRINT '✓ InsertOtpRecord procedure created';
    
    -- ============================================================================
    -- OTP STATUS MANAGEMENT
    -- ============================================================================
    
    PRINT 'Creating OTP status management procedures...';
    
    -- ProcessFailedOtpAttempt: Handle failed OTP attempts
    EXEC ('
    CREATE PROCEDURE dbo.ProcessFailedOtpAttempt
        @OtpUniqueId UNIQUEIDENTIFIER,
        @FlowUniqueId UNIQUEIDENTIFIER,
        @IpAddress NVARCHAR(45) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @Success BIT = 0;
        DECLARE @Message NVARCHAR(255);
        
        BEGIN TRY
            -- Validate inputs
            IF dbo.ValidateGuid(CAST(@OtpUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Message = ''Invalid OtpUniqueId format'';
                GOTO ReturnResult;
            END
            
            IF dbo.ValidateGuid(CAST(@FlowUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Message = ''Invalid FlowUniqueId format'';
                GOTO ReturnResult;
            END
            
            -- Insert failed attempt record
            INSERT INTO dbo.FailedOtpAttempts (OtpUniqueId, FlowUniqueId, AttemptTime)
            VALUES (@OtpUniqueId, @FlowUniqueId, GETUTCDATE());
            
            SET @Success = 1;
            SET @Message = ''Failed OTP attempt recorded successfully'';
            
            -- Log audit event
            EXEC dbo.LogAuditEvent
                @EventType = ''OTP_ATTEMPT_FAILED'',
                @Details = ''Failed OTP attempt recorded'',
                @IpAddress = @IpAddress,
                @AdditionalData = CONCAT(''OtpId:'', @OtpUniqueId, '', FlowId:'', @FlowUniqueId);
                
        END TRY
        BEGIN CATCH
            SET @Message = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''ProcessFailedOtpAttempt failed'';
        END CATCH
        
        ReturnResult:
        SELECT @Success AS Success, @Message AS Message;
    END;
    ');
    
    -- UpdateOtpStatus: Enhanced OTP status updates with validation
    EXEC ('
    CREATE PROCEDURE dbo.UpdateOtpStatus
        @OtpUniqueId UNIQUEIDENTIFIER, 
        @NewStatus NVARCHAR(20),
        @IpAddress NVARCHAR(45) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        SET XACT_ABORT ON;
        
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        
        DECLARE @CurrentStatus NVARCHAR(20);
        DECLARE @FlowId BIGINT;
        DECLARE @FlowUniqueId UNIQUEIDENTIFIER;
        DECLARE @Success BIT = 0;
        DECLARE @Message NVARCHAR(255);
        DECLARE @RowsAffected INT = 0;
        
        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate OTP ID
            IF dbo.ValidateGuid(CAST(@OtpUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Message = ''Invalid OtpUniqueId format'';
                GOTO ReturnResult;
            END
            
            -- Validate IP address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @Message = ''Invalid IP address format'';
                GOTO ReturnResult;
            END
            
            -- ================================================================
            -- OTP AND FLOW VALIDATION
            -- ================================================================
            
            -- Get current OTP and flow information
            SELECT 
                @CurrentStatus = o.Status, 
                @FlowId = vf.Id, 
                @FlowUniqueId = vf.UniqueId
            FROM dbo.OtpRecords AS o 
            INNER JOIN dbo.VerificationFlows AS vf ON o.FlowUniqueId = vf.UniqueId
            WHERE o.UniqueId = @OtpUniqueId 
              AND o.IsDeleted = 0 
              AND vf.IsDeleted = 0;

            IF @CurrentStatus IS NULL
            BEGIN
                SET @Message = ''OTP not found or has been deleted'';
                GOTO ReturnResult;
            END
            
            -- Validate status transition
            DECLARE @IsValidTransition BIT, @TransitionError NVARCHAR(255);
            EXEC dbo.ValidateOtpTransition @CurrentStatus, @NewStatus, @IsValidTransition OUTPUT, @TransitionError OUTPUT;
            
            IF @IsValidTransition = 0
            BEGIN
                SET @Message = @TransitionError;
                GOTO ReturnResult;
            END
            
            -- Check if it''s a no-op transition
            IF @CurrentStatus = @NewStatus
            BEGIN
                SET @Success = 1;
                SET @Message = ''OTP status is already '' + @NewStatus;
                GOTO ReturnResult;
            END
            
            -- ================================================================
            -- STATUS UPDATE
            -- ================================================================
            
            -- Update OTP status
            UPDATE dbo.OtpRecords 
            SET Status = @NewStatus, 
                IsActive = CASE WHEN @NewStatus = ''pending'' THEN 1 ELSE 0 END,
                UpdatedAt = GETUTCDATE()
            WHERE UniqueId = @OtpUniqueId 
              AND IsDeleted = 0;
            
            SET @RowsAffected = @@ROWCOUNT;
            
            IF @RowsAffected = 0
            BEGIN
                SET @Message = ''Failed to update OTP: no rows affected'';
                GOTO ReturnResult;
            END

            -- Handle specific status transitions
            IF @NewStatus = ''failed''
            BEGIN
                -- Record failed attempt
                EXEC dbo.ProcessFailedOtpAttempt @OtpUniqueId, @FlowUniqueId, @IpAddress;
            END
            ELSE IF @NewStatus = ''verified''
            BEGIN
                -- Update verification flow to verified
                UPDATE dbo.VerificationFlows 
                SET Status = ''verified'', UpdatedAt = GETUTCDATE()
                WHERE Id = @FlowId AND Status = ''pending'';
                
                SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
                
                -- Log successful verification
                EXEC dbo.LogAuditEvent
                    @EventType = ''OTP_VERIFIED'',
                    @Details = ''OTP successfully verified'',
                    @IpAddress = @IpAddress,
                    @AdditionalData = CONCAT(''OtpId:'', @OtpUniqueId, '', FlowId:'', @FlowUniqueId);
            END

            SET @Success = 1;
            SET @Message = ''OTP status updated successfully from '' + @CurrentStatus + '' to '' + @NewStatus;
            
        END TRY
        BEGIN CATCH
            SET @Message = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''UpdateOtpStatus failed'';
        END CATCH
        
        ReturnResult:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = ''UpdateOtpStatus'',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = ''milliseconds'',
            @AdditionalData = CONCAT(''Success:'', @Success, '', RowsAffected:'', @RowsAffected);
        
        -- Return results
        SELECT @Success AS Success, @Message AS Message;
    END;
    ');
    
    PRINT '✓ OTP status management procedures created';
    
    -- ============================================================================
    -- VERIFICATION FLOW STATUS MANAGEMENT
    -- ============================================================================
    
    PRINT 'Creating verification flow status management procedures...';
    
    -- UpdateVerificationFlowStatus: Enhanced flow status updates
    EXEC ('
    CREATE PROCEDURE dbo.UpdateVerificationFlowStatus
        @FlowUniqueId UNIQUEIDENTIFIER, 
        @NewStatus NVARCHAR(20),
        @IpAddress NVARCHAR(45) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        SET XACT_ABORT ON;
        
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @RowsAffected INT = 0;
        DECLARE @Success BIT = 0;
        DECLARE @Message NVARCHAR(255);
        DECLARE @CurrentStatus NVARCHAR(20);
        
        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate Flow ID
            IF dbo.ValidateGuid(CAST(@FlowUniqueId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Message = ''Invalid FlowUniqueId format'';
                GOTO ReturnResult;
            END
            
            -- Validate new status
            IF @NewStatus NOT IN (''pending'', ''verified'', ''expired'', ''failed'', ''completed'')
            BEGIN
                SET @Message = ''Invalid verification flow status'';
                GOTO ReturnResult;
            END
            
            -- Validate IP address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @Message = ''Invalid IP address format'';
                GOTO ReturnResult;
            END
            
            -- ================================================================
            -- FLOW VALIDATION AND UPDATE
            -- ================================================================
            
            -- Get current status
            SELECT @CurrentStatus = Status
            FROM dbo.VerificationFlows
            WHERE UniqueId = @FlowUniqueId AND IsDeleted = 0;
            
            IF @CurrentStatus IS NULL
            BEGIN
                SET @Message = ''Verification flow not found or has been deleted'';
                GOTO ReturnResult;
            END
            
            -- Check if it''s a no-op transition
            IF @CurrentStatus = @NewStatus
            BEGIN
                SET @Success = 1;
                SET @Message = ''Verification flow status is already '' + @NewStatus;
                GOTO ReturnResult;
            END
            
            -- Update verification flow
            UPDATE dbo.VerificationFlows
            SET Status = @NewStatus, 
                ExpiresAt = CASE 
                    WHEN @NewStatus = ''verified'' THEN DATEADD(HOUR, 24, GETUTCDATE()) 
                    ELSE ExpiresAt 
                END,
                UpdatedAt = GETUTCDATE()
            WHERE UniqueId = @FlowUniqueId AND IsDeleted = 0;
            
            SET @RowsAffected = @@ROWCOUNT;
            
            IF @RowsAffected = 0
            BEGIN
                SET @Message = ''Failed to update verification flow: no rows affected'';
                GOTO ReturnResult;
            END
            
            SET @Success = 1;
            SET @Message = ''Verification flow status updated from '' + @CurrentStatus + '' to '' + @NewStatus;
            
            -- Log status change
            EXEC dbo.LogAuditEvent
                @EventType = ''VERIFICATION_FLOW_STATUS_CHANGED'',
                @Details = @Message,
                @IpAddress = @IpAddress,
                @AdditionalData = CONCAT(''FlowId:'', @FlowUniqueId, '', OldStatus:'', @CurrentStatus, '', NewStatus:'', @NewStatus);
            
        END TRY
        BEGIN CATCH
            SET @Message = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''UpdateVerificationFlowStatus failed'';
        END CATCH
        
        ReturnResult:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = ''UpdateVerificationFlowStatus'',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = ''milliseconds'',
            @AdditionalData = CONCAT(''Success:'', @Success, '', RowsAffected:'', @RowsAffected);
        
        -- Return results  
        SELECT @Success AS Success, @Message AS Message, @RowsAffected AS RowsAffected;
    END;
    ');
    
    PRINT '✓ Verification flow status management procedures created';
    
    -- ============================================================================
    -- PROCEDURE VALIDATION
    -- ============================================================================
    
    PRINT 'Validating OTP management procedures...';
    
    DECLARE @ProcedureCount INT;
    SELECT @ProcedureCount = COUNT(*)
    FROM sys.procedures p
    INNER JOIN sys.schemas s ON p.schema_id = s.schema_id
    WHERE s.name = 'dbo' 
    AND p.name IN (
        'ValidateOtpTransition', 'InsertOtpRecord', 'ProcessFailedOtpAttempt',
        'UpdateOtpStatus', 'UpdateVerificationFlowStatus'
    );
    
    IF @ProcedureCount = 5
        PRINT '✓ All 5 OTP management procedures created successfully';
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
    PRINT 'Layer 4.4: OTP Management Procedures Completed Successfully';
    PRINT 'Procedures created: ' + CAST(@ProcedureCount AS NVARCHAR(10));
    PRINT 'Features: OTP creation, status management, validation, failed attempt tracking';
    PRINT 'Security: Status transition validation, comprehensive audit trail';
    PRINT 'Layer 4: Core Business Procedures - COMPLETED';
    PRINT 'Next: Layer 5 - Advanced Features';
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
    PRINT 'ERROR in Layer 4.4: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO