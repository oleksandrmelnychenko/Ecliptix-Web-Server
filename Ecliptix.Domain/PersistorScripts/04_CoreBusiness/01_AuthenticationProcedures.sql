/*
================================================================================
Layer 4.1: Authentication Procedures
================================================================================
Purpose: Core authentication context management procedures with enhanced security
Dependencies: Layers 1-3 (Infrastructure, Domain Tables, Constraints)
Execution Order: 8th - Authentication business logic layer

Features:
- Authentication context creation and validation
- Session management and security
- Rate limiting and lockout mechanisms
- Comprehensive audit trail
- Performance monitoring
- Configuration-driven parameters

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
PRINT 'Layer 4.1: Authentication Procedures';
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
VALUES (@DeploymentId, '01_AuthenticationProcedures.sql', 7, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- CLEANUP EXISTING PROCEDURES
    -- ============================================================================
    
    PRINT 'Cleaning up existing authentication procedures...';
    
    IF OBJECT_ID('dbo.CreateAuthenticationContext', 'P') IS NOT NULL DROP PROCEDURE dbo.CreateAuthenticationContext;
    IF OBJECT_ID('dbo.ValidateAuthenticationContext', 'P') IS NOT NULL DROP PROCEDURE dbo.ValidateAuthenticationContext;
    IF OBJECT_ID('dbo.RefreshAuthenticationContext', 'P') IS NOT NULL DROP PROCEDURE dbo.RefreshAuthenticationContext;
    IF OBJECT_ID('dbo.InvalidateAuthenticationContext', 'P') IS NOT NULL DROP PROCEDURE dbo.InvalidateAuthenticationContext;
    IF OBJECT_ID('dbo.InvalidateAllContextsForMobile', 'P') IS NOT NULL DROP PROCEDURE dbo.InvalidateAllContextsForMobile;
    IF OBJECT_ID('dbo.CleanupExpiredContexts', 'P') IS NOT NULL DROP PROCEDURE dbo.CleanupExpiredContexts;
    IF OBJECT_ID('dbo.UpdateAuthenticationState', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateAuthenticationState;
    IF OBJECT_ID('dbo.GetAuthenticationState', 'P') IS NOT NULL DROP PROCEDURE dbo.GetAuthenticationState;
    
    PRINT '✓ Existing authentication procedures cleaned up';
    
    -- ============================================================================
    -- AUTHENTICATION CONTEXT CREATION
    -- ============================================================================
    
    PRINT 'Creating authentication context management procedures...';
    
    -- CreateAuthenticationContext: Enhanced context creation with validation
    EXEC ('
    CREATE PROCEDURE dbo.CreateAuthenticationContext
        @ContextToken VARBINARY(64),
        @MembershipId UNIQUEIDENTIFIER,
        @MobileNumberId UNIQUEIDENTIFIER,
        @ExpiresAt DATETIME2(7),
        @IpAddress NVARCHAR(45) = NULL,
        @UserAgent NVARCHAR(500) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        SET XACT_ABORT ON;
        
        -- Performance monitoring variables
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @ProcName NVARCHAR(100) = ''CreateAuthenticationContext'';
        DECLARE @RowsAffected INT = 0;
        
        -- Operation variables
        DECLARE @ContextId BIGINT;
        DECLARE @Success BIT = 0;
        DECLARE @Message NVARCHAR(255) = '''';
        DECLARE @ValidationErrors NVARCHAR(MAX);
        DECLARE @IsValidInput BIT;
        DECLARE @Parameters NVARCHAR(MAX);
        
        -- Build parameters for logging (mask sensitive data)
        SET @Parameters = CONCAT(
            ''MembershipId='', @MembershipId,
            '', MobileNumberId='', @MobileNumberId,
            '', ExpiresAt='', FORMAT(@ExpiresAt, ''yyyy-MM-dd HH:mm:ss''),
            '', IpAddress='', ISNULL(dbo.MaskSensitiveData(@IpAddress, ''PARTIAL''), ''NULL''),
            '', UserAgent='', CASE WHEN @UserAgent IS NULL THEN ''NULL'' ELSE ''[PROVIDED]'' END
        );

        BEGIN TRY
            -- ================================================================
            -- INPUT VALIDATION
            -- ================================================================
            
            -- Validate context token
            IF @ContextToken IS NULL OR DATALENGTH(@ContextToken) != 64
            BEGIN
                SET @Message = ''Context token must be exactly 64 bytes'';
                GOTO HandleValidationError;
            END
            
            -- Validate MembershipId using validation framework
            IF dbo.ValidateGuid(CAST(@MembershipId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Message = ''Invalid MembershipId format'';
                GOTO HandleValidationError;
            END
            
            -- Validate MobileNumberId
            IF dbo.ValidateGuid(CAST(@MobileNumberId AS NVARCHAR(50))) = 0
            BEGIN
                SET @Message = ''Invalid MobileNumberId format'';
                GOTO HandleValidationError;
            END
            
            -- Validate ExpiresAt
            IF @ExpiresAt IS NULL OR @ExpiresAt <= GETUTCDATE()
            BEGIN
                SET @Message = ''ExpiresAt must be a future date'';
                GOTO HandleValidationError;
            END
            
            -- Validate maximum expiration time (configurable)
            DECLARE @MaxExpirationHours INT = CAST(dbo.GetConfigValue(''Authentication.ContextExpirationHours'') AS INT);
            IF @ExpiresAt > DATEADD(HOUR, @MaxExpirationHours, GETUTCDATE())
            BEGIN
                SET @Message = CONCAT(''ExpiresAt cannot exceed '', @MaxExpirationHours, '' hours from now'');
                GOTO HandleValidationError;
            END
            
            -- Validate IP Address if provided
            IF @IpAddress IS NOT NULL AND dbo.ValidateIpAddress(@IpAddress) = 0
            BEGIN
                SET @Message = ''Invalid IP address format'';
                GOTO HandleValidationError;
            END
            
            -- Sanitize UserAgent
            IF LEN(@UserAgent) > 500
                SET @UserAgent = LEFT(@UserAgent, 497) + ''...'';
            
            -- ================================================================
            -- BUSINESS LOGIC VALIDATION
            -- ================================================================
            
            -- Check if membership exists and is active
            IF NOT EXISTS (
                SELECT 1 FROM dbo.Memberships 
                WHERE UniqueId = @MembershipId 
                  AND IsDeleted = 0 
                  AND Status = ''active''
            )
            BEGIN
                SET @Message = ''Membership not found or inactive'';
                GOTO HandleValidationError;
            END
            
            -- Check if mobile number exists
            IF NOT EXISTS (
                SELECT 1 FROM dbo.PhoneNumbers 
                WHERE UniqueId = @MobileNumberId 
                  AND IsDeleted = 0
            )
            BEGIN
                SET @Message = ''Mobile number not found'';
                GOTO HandleValidationError;
            END
            
            -- Check concurrent session limit
            DECLARE @MaxSessionsPerUser INT = CAST(dbo.GetConfigValue(''Authentication.MaxSessionsPerUser'') AS INT);
            DECLARE @CurrentActiveSessions INT;
            
            SELECT @CurrentActiveSessions = COUNT(*)
            FROM dbo.AuthenticationContexts
            WHERE MembershipId = @MembershipId
              AND IsActive = 1
              AND IsDeleted = 0
              AND ExpiresAt > GETUTCDATE();
            
            IF @CurrentActiveSessions >= @MaxSessionsPerUser
            BEGIN
                -- Invalidate oldest session to make room
                DECLARE @OldestContextId BIGINT;
                SELECT TOP 1 @OldestContextId = Id
                FROM dbo.AuthenticationContexts
                WHERE MembershipId = @MembershipId
                  AND IsActive = 1
                  AND IsDeleted = 0
                ORDER BY CreatedAt ASC;
                
                UPDATE dbo.AuthenticationContexts
                SET IsActive = 0,
                    ContextState = ''invalidated'',
                    UpdatedAt = GETUTCDATE()
                WHERE Id = @OldestContextId;
                
                SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
                
                -- Log session displacement
                EXEC dbo.LogAuditEvent 
                    @EventType = ''SESSION_DISPLACED'',
                    @Details = ''Oldest session invalidated due to concurrent session limit'',
                    @UserId = @MembershipId,
                    @IpAddress = @IpAddress,
                    @AdditionalData = CAST(@OldestContextId AS NVARCHAR(20));
            END
            
            -- ================================================================
            -- CONTEXT CREATION
            -- ================================================================
            
            -- Check for circuit breaker
            DECLARE @CircuitOpen BIT, @CircuitError NVARCHAR(255);
            EXEC dbo.CheckCircuitBreaker ''AuthContextCreate'', @CircuitOpen OUTPUT, @CircuitError OUTPUT;
            
            IF @CircuitOpen = 1
            BEGIN
                SET @Message = @CircuitError;
                GOTO HandleValidationError;
            END
            
            -- Create new authentication context
            INSERT INTO dbo.AuthenticationContexts (
                ContextToken, MembershipId, MobileNumberId, ExpiresAt, 
                IpAddress, UserAgent, IsActive, ContextState
            )
            VALUES (
                @ContextToken, @MembershipId, @MobileNumberId, @ExpiresAt,
                @IpAddress, @UserAgent, 1, ''active''
            );

            SET @ContextId = SCOPE_IDENTITY();
            SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
            
            -- Reset authentication state for the mobile number (successful auth)
            MERGE dbo.AuthenticationStates AS target
            USING (SELECT @MobileNumberId AS MobileNumberId) AS source
            ON target.MobileNumberId = source.MobileNumberId
            WHEN MATCHED THEN
                UPDATE SET 
                    RecentAttempts = 0,
                    WindowStartTime = GETUTCDATE(),
                    LastAttemptTime = GETUTCDATE(),
                    IsLocked = 0,
                    LockedUntil = NULL,
                    LastSyncTime = GETUTCDATE(),
                    UpdatedAt = GETUTCDATE()
            WHEN NOT MATCHED THEN
                INSERT (MobileNumberId, RecentAttempts, WindowStartTime, LastAttemptTime, IsLocked, LastSyncTime)
                VALUES (@MobileNumberId, 0, GETUTCDATE(), GETUTCDATE(), 0, GETUTCDATE());
            
            SET @RowsAffected = @RowsAffected + @@ROWCOUNT;
            
            -- Record circuit breaker success
            EXEC dbo.RecordCircuitBreakerSuccess ''AuthContextCreate'';
            
            -- Operation successful
            SET @Success = 1;
            SET @Message = CONCAT(''Authentication context created successfully. ContextId: '', @ContextId);
            
            -- Log audit event for successful context creation
            EXEC dbo.LogAuditEvent 
                @EventType = ''AUTH_CONTEXT_CREATED'',
                @Details = ''New authentication context created'',
                @UserId = @MembershipId,
                @IpAddress = @IpAddress,
                @AdditionalData = CAST(@ContextId AS NVARCHAR(20));
            
            GOTO SuccessExit;
            
            -- ================================================================
            -- ERROR HANDLING
            -- ================================================================
            
            HandleValidationError:
            -- Record circuit breaker failure for systemic issues
            IF @Message LIKE ''%not found%'' OR @Message LIKE ''%inactive%''
                EXEC dbo.RecordCircuitBreakerFailure ''AuthContextCreate'', @Message;
            
            -- Log validation error
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''WARNING'',
                @AdditionalInfo = @Parameters;
                
            -- Log audit event for failed validation
            EXEC dbo.LogAuditEvent
                @EventType = ''AUTH_CONTEXT_CREATION_FAILED'',
                @Details = @Message,
                @UserId = @MembershipId,
                @IpAddress = @IpAddress,
                @Success = 0;

        END TRY
        BEGIN CATCH
            SET @Success = 0;
            SET @Message = ERROR_MESSAGE();
            
            -- Record circuit breaker failure
            EXEC dbo.RecordCircuitBreakerFailure ''AuthContextCreate'', @Message;
            
            -- Log the error
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = @Parameters;
                
            -- Log audit event for error
            EXEC dbo.LogAuditEvent
                @EventType = ''AUTH_CONTEXT_CREATION_ERROR'',
                @Details = @Message,
                @UserId = @MembershipId,
                @IpAddress = @IpAddress,
                @Success = 0;
        END CATCH
        
        SuccessExit:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = ''CreateAuthenticationContext'',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = ''milliseconds'',
            @AdditionalData = CONCAT(''Success:'', @Success, '', RowsAffected:'', @RowsAffected);
        
        -- Return results
        SELECT 
            @ContextId AS ContextId, 
            @Success AS Success, 
            @Message AS Message;
    END;
    ');
    
    PRINT '✓ CreateAuthenticationContext procedure created';
    
    -- ============================================================================
    -- AUTHENTICATION CONTEXT VALIDATION
    -- ============================================================================
    
    -- ValidateAuthenticationContext: Enhanced validation with security tracking
    EXEC ('
    CREATE PROCEDURE dbo.ValidateAuthenticationContext
        @ContextToken VARBINARY(64)
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @ProcName NVARCHAR(100) = ''ValidateAuthenticationContext'';
        
        DECLARE @ContextId BIGINT;
        DECLARE @MembershipId UNIQUEIDENTIFIER;
        DECLARE @MobileNumberId UNIQUEIDENTIFIER;
        DECLARE @ExpiresAt DATETIME2(7);
        DECLARE @ContextState NVARCHAR(20);
        DECLARE @IsValid BIT = 0;
        DECLARE @Message NVARCHAR(255);
        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

        BEGIN TRY
            -- Input validation
            IF @ContextToken IS NULL OR DATALENGTH(@ContextToken) != 64
            BEGIN
                SET @Message = ''Invalid context token provided'';
                
                -- Log potential security issue
                EXEC dbo.LogAuditEvent 
                    @EventType = ''INVALID_TOKEN_FORMAT'',
                    @Details = @Message,
                    @Success = 0;
                    
                GOTO ExitWithResult;
            END

            -- Retrieve context information
            SELECT 
                @ContextId = Id,
                @MembershipId = MembershipId,
                @MobileNumberId = MobileNumberId,
                @ExpiresAt = ExpiresAt,
                @ContextState = ContextState
            FROM dbo.AuthenticationContexts
            WHERE ContextToken = @ContextToken
              AND IsActive = 1
              AND IsDeleted = 0;

            -- Check if context exists
            IF @ContextId IS NULL
            BEGIN
                SET @Message = ''Authentication context not found or inactive'';
                
                -- Log potential security issue
                EXEC dbo.LogAuditEvent 
                    @EventType = ''CONTEXT_NOT_FOUND'',
                    @Details = @Message,
                    @Success = 0;
                    
                GOTO ExitWithResult;
            END

            -- Check expiration
            IF @CurrentTime >= @ExpiresAt
            BEGIN
                -- Mark as expired
                UPDATE dbo.AuthenticationContexts 
                SET ContextState = ''expired'', 
                    IsActive = 0,
                    UpdatedAt = @CurrentTime
                WHERE Id = @ContextId;

                SET @Message = ''Authentication context has expired'';
                
                -- Log expiration event
                EXEC dbo.LogAuditEvent
                    @EventType = ''CONTEXT_EXPIRED'',
                    @Details = @Message,
                    @UserId = @MembershipId,
                    @AdditionalData = CAST(@ContextId AS NVARCHAR(20));
                    
                GOTO ExitWithResult;
            END

            -- Check context state
            IF @ContextState != ''active''
            BEGIN
                SET @Message = CONCAT(''Authentication context is not active. State: '', @ContextState);
                
                EXEC dbo.LogAuditEvent
                    @EventType = ''CONTEXT_INACTIVE'',
                    @Details = @Message,
                    @UserId = @MembershipId,
                    @AdditionalData = CAST(@ContextId AS NVARCHAR(20));
                    
                GOTO ExitWithResult;
            END

            -- Update last accessed time for valid context
            UPDATE dbo.AuthenticationContexts 
            SET LastAccessedAt = @CurrentTime,
                UpdatedAt = @CurrentTime
            WHERE Id = @ContextId;

            SET @IsValid = 1;
            SET @Message = ''Authentication context is valid'';
            
            -- Log successful validation (if detailed logging enabled)
            IF CAST(dbo.GetConfigValue(''Audit.LogValidations'') AS BIT) = 1
            BEGIN
                EXEC dbo.LogAuditEvent
                    @EventType = ''CONTEXT_VALIDATED'',
                    @Details = @Message,
                    @UserId = @MembershipId,
                    @AdditionalData = CAST(@ContextId AS NVARCHAR(20));
            END

        END TRY
        BEGIN CATCH
            SET @Message = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''ValidateAuthenticationContext failed'';
        END CATCH

        ExitWithResult:
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        EXEC dbo.LogPerformanceMetric
            @MetricName = ''ValidateAuthenticationContext'',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = ''milliseconds'',
            @AdditionalData = CONCAT(''IsValid:'', @IsValid);
            
        -- Return validation results
        SELECT 
            @IsValid AS IsValid, 
            @Message AS Message,
            CASE WHEN @IsValid = 1 THEN @ContextId ELSE NULL END AS ContextId,
            CASE WHEN @IsValid = 1 THEN @MembershipId ELSE NULL END AS MembershipId,
            CASE WHEN @IsValid = 1 THEN @MobileNumberId ELSE NULL END AS MobileNumberId;
    END;
    ');
    
    PRINT '✓ ValidateAuthenticationContext procedure created';
    
    -- ============================================================================
    -- AUTHENTICATION CONTEXT MANAGEMENT
    -- ============================================================================
    
    -- RefreshAuthenticationContext: Extend context expiration
    EXEC ('
    CREATE PROCEDURE dbo.RefreshAuthenticationContext
        @ContextToken VARBINARY(64),
        @NewExpiresAt DATETIME2(7)
    AS
    BEGIN
        SET NOCOUNT ON;

        DECLARE @RowsAffected INT;
        DECLARE @Success BIT = 0;
        DECLARE @Message NVARCHAR(255);
        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
        DECLARE @ContextId BIGINT;

        BEGIN TRY
            -- Validate new expiration time
            DECLARE @MaxExpirationHours INT = CAST(dbo.GetConfigValue(''Authentication.ContextExpirationHours'') AS INT);
            IF @NewExpiresAt > DATEADD(HOUR, @MaxExpirationHours, @CurrentTime)
            BEGIN
                SET @Message = CONCAT(''New expiration time cannot exceed '', @MaxExpirationHours, '' hours from now'');
                GOTO ExitWithResult;
            END

            -- Get context ID for logging
            SELECT @ContextId = Id FROM dbo.AuthenticationContexts 
            WHERE ContextToken = @ContextToken AND IsActive = 1 AND IsDeleted = 0;

            -- Refresh the context
            UPDATE dbo.AuthenticationContexts
            SET ExpiresAt = @NewExpiresAt,
                LastAccessedAt = @CurrentTime,
                UpdatedAt = @CurrentTime
            WHERE ContextToken = @ContextToken
              AND IsActive = 1
              AND IsDeleted = 0
              AND ContextState = ''active''
              AND ExpiresAt > @CurrentTime;

            SET @RowsAffected = @@ROWCOUNT;

            IF @RowsAffected > 0
            BEGIN
                SET @Success = 1;
                SET @Message = ''Authentication context refreshed successfully'';
                
                -- Log refresh event
                EXEC dbo.LogAuditEvent 
                    @EventType = ''CONTEXT_REFRESHED'',
                    @Details = @Message,
                    @AdditionalData = CAST(@ContextId AS NVARCHAR(20));
            END
            ELSE
            BEGIN
                SET @Message = ''Authentication context not found, expired, or inactive'';
                
                EXEC dbo.LogAuditEvent 
                    @EventType = ''CONTEXT_REFRESH_FAILED'',
                    @Details = @Message,
                    @Success = 0;
            END
        END TRY
        BEGIN CATCH
            SET @Message = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''RefreshAuthenticationContext failed'';
        END CATCH

        ExitWithResult:
        SELECT @Success AS Success, @Message AS Message;
    END;
    ');
    
    -- InvalidateAuthenticationContext: Invalidate single context
    EXEC ('
    CREATE PROCEDURE dbo.InvalidateAuthenticationContext
        @ContextToken VARBINARY(64)
    AS
    BEGIN
        SET NOCOUNT ON;

        DECLARE @RowsAffected INT;
        DECLARE @Success BIT = 0;
        DECLARE @Message NVARCHAR(255);
        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
        DECLARE @ContextId BIGINT;
        DECLARE @MembershipId UNIQUEIDENTIFIER;

        BEGIN TRY
            -- Get context details for logging
            SELECT @ContextId = Id, @MembershipId = MembershipId 
            FROM dbo.AuthenticationContexts 
            WHERE ContextToken = @ContextToken AND IsActive = 1 AND IsDeleted = 0;

            -- Invalidate the context
            UPDATE dbo.AuthenticationContexts
            SET IsActive = 0,
                ContextState = ''invalidated'',
                UpdatedAt = @CurrentTime
            WHERE ContextToken = @ContextToken
              AND IsActive = 1
              AND IsDeleted = 0;

            SET @RowsAffected = @@ROWCOUNT;

            IF @RowsAffected > 0
            BEGIN
                SET @Success = 1;
                SET @Message = ''Authentication context invalidated successfully'';
                
                -- Log invalidation event
                EXEC dbo.LogAuditEvent 
                    @EventType = ''CONTEXT_INVALIDATED'',
                    @Details = @Message,
                    @UserId = @MembershipId,
                    @AdditionalData = CAST(@ContextId AS NVARCHAR(20));
            END
            ELSE
            BEGIN
                SET @Message = ''Authentication context not found or already inactive'';
                
                EXEC dbo.LogAuditEvent 
                    @EventType = ''CONTEXT_INVALIDATION_FAILED'',
                    @Details = @Message,
                    @Success = 0;
            END
        END TRY
        BEGIN CATCH
            SET @Message = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @Message,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''InvalidateAuthenticationContext failed'';
        END CATCH

        SELECT @Success AS Success, @Message AS Message;
    END;
    ');
    
    -- InvalidateAllContextsForMobile: Mass invalidation for security
    EXEC ('
    CREATE PROCEDURE dbo.InvalidateAllContextsForMobile
        @MobileNumberId UNIQUEIDENTIFIER
    AS
    BEGIN
        SET NOCOUNT ON;

        DECLARE @ContextsInvalidated INT;
        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

        BEGIN TRY
            -- Validate mobile number ID
            IF dbo.ValidateGuid(CAST(@MobileNumberId AS NVARCHAR(50))) = 0
            BEGIN
                SELECT 0 AS Success, ''Invalid MobileNumberId format'' AS Message;
                RETURN;
            END

            -- Invalidate all active contexts for the mobile number
            UPDATE dbo.AuthenticationContexts
            SET IsActive = 0,
                ContextState = ''invalidated'',
                UpdatedAt = @CurrentTime
            WHERE MobileNumberId = @MobileNumberId
              AND IsActive = 1
              AND IsDeleted = 0;

            SET @ContextsInvalidated = @@ROWCOUNT;

            -- Log mass invalidation event
            EXEC dbo.LogAuditEvent 
                @EventType = ''ALL_CONTEXTS_INVALIDATED'',
                @Details = CONCAT(''All contexts invalidated for mobile number: '', @ContextsInvalidated, '' affected''),
                @AdditionalData = CAST(@MobileNumberId AS NVARCHAR(36));

            SELECT 1 AS Success, 
                   @ContextsInvalidated AS ContextsInvalidated,
                   ''All authentication contexts invalidated successfully'' AS Message;
        END TRY
        BEGIN CATCH
            DECLARE @ErrorMsg NVARCHAR(255) = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @ErrorMsg,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''InvalidateAllContextsForMobile failed'';
                
            SELECT 0 AS Success, @ErrorMsg AS Message;
        END CATCH
    END;
    ');
    
    PRINT '✓ Authentication context management procedures created';
    
    -- ============================================================================
    -- AUTHENTICATION STATE MANAGEMENT
    -- ============================================================================
    
    PRINT 'Creating authentication state management procedures...';
    
    -- UpdateAuthenticationState: Manage authentication states
    EXEC ('
    CREATE PROCEDURE dbo.UpdateAuthenticationState
        @MobileNumberId UNIQUEIDENTIFIER,
        @RecentAttempts INT,
        @WindowStartTime DATETIME2(7),
        @IsLocked BIT = 0,
        @LockedUntil DATETIME2(7) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;

        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

        BEGIN TRY
            -- Validate input
            IF dbo.ValidateGuid(CAST(@MobileNumberId AS NVARCHAR(50))) = 0
            BEGIN
                SELECT 0 AS Success, ''Invalid MobileNumberId format'' AS Message;
                RETURN;
            END

            IF @RecentAttempts < 0
            BEGIN
                SELECT 0 AS Success, ''RecentAttempts cannot be negative'' AS Message;
                RETURN;
            END

            -- Update or insert authentication state
            MERGE dbo.AuthenticationStates AS target
            USING (SELECT @MobileNumberId AS MobileNumberId) AS source
            ON target.MobileNumberId = source.MobileNumberId
            WHEN MATCHED THEN
                UPDATE SET 
                    RecentAttempts = @RecentAttempts,
                    WindowStartTime = @WindowStartTime,
                    LastAttemptTime = @CurrentTime,
                    IsLocked = @IsLocked,
                    LockedUntil = @LockedUntil,
                    LastSyncTime = @CurrentTime,
                    UpdatedAt = @CurrentTime
            WHEN NOT MATCHED THEN
                INSERT (MobileNumberId, RecentAttempts, WindowStartTime, LastAttemptTime, 
                        IsLocked, LockedUntil, LastSyncTime)
                VALUES (@MobileNumberId, @RecentAttempts, @WindowStartTime, @CurrentTime,
                        @IsLocked, @LockedUntil, @CurrentTime);

            -- Log significant state changes
            IF @IsLocked = 1
            BEGIN
                EXEC dbo.LogAuditEvent 
                    @EventType = ''ACCOUNT_LOCKED'',
                    @Details = CONCAT(''Account locked until '', FORMAT(@LockedUntil, ''yyyy-MM-dd HH:mm:ss'')),
                    @AdditionalData = CAST(@MobileNumberId AS NVARCHAR(36));
            END

            SELECT 1 AS Success, ''Authentication state updated successfully'' AS Message;
        END TRY
        BEGIN CATCH
            DECLARE @ErrorMsg NVARCHAR(255) = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @ErrorMsg,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''UpdateAuthenticationState failed'';
                
            SELECT 0 AS Success, @ErrorMsg AS Message;
        END CATCH
    END;
    ');
    
    -- GetAuthenticationState: Retrieve authentication state
    EXEC ('
    CREATE PROCEDURE dbo.GetAuthenticationState
        @MobileNumberId UNIQUEIDENTIFIER
    AS
    BEGIN
        SET NOCOUNT ON;

        BEGIN TRY
            -- Validate input
            IF dbo.ValidateGuid(CAST(@MobileNumberId AS NVARCHAR(50))) = 0
            BEGIN
                SELECT NULL AS MobileNumberId, ''Invalid MobileNumberId format'' AS ErrorMessage;
                RETURN;
            END

            -- Get authentication state or return default
            SELECT 
                MobileNumberId,
                RecentAttempts,
                WindowStartTime,
                LastAttemptTime,
                IsLocked,
                LockedUntil,
                LastSyncTime,
                CreatedAt,
                UpdatedAt
            FROM dbo.AuthenticationStates
            WHERE MobileNumberId = @MobileNumberId;

            -- If no state exists, return default values
            IF @@ROWCOUNT = 0
            BEGIN
                SELECT 
                    @MobileNumberId AS MobileNumberId,
                    0 AS RecentAttempts,
                    GETUTCDATE() AS WindowStartTime,
                    NULL AS LastAttemptTime,
                    0 AS IsLocked,
                    NULL AS LockedUntil,
                    GETUTCDATE() AS LastSyncTime,
                    GETUTCDATE() AS CreatedAt,
                    GETUTCDATE() AS UpdatedAt;
            END
        END TRY
        BEGIN CATCH
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = ''GetAuthenticationState failed'';
                
            SELECT NULL AS MobileNumberId, ERROR_MESSAGE() AS ErrorMessage;
        END CATCH
    END;
    ');
    
    PRINT '✓ Authentication state management procedures created';
    
    -- ============================================================================
    -- CLEANUP AND MAINTENANCE
    -- ============================================================================
    
    PRINT 'Creating cleanup and maintenance procedures...';
    
    -- CleanupExpiredContexts: Enhanced cleanup with monitoring
    EXEC ('
    CREATE PROCEDURE dbo.CleanupExpiredContexts
        @BatchSize INT = NULL,
        @OlderThanHours INT = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @ProcName NVARCHAR(100) = ''CleanupExpiredContexts'';
        
        -- Use configuration values if parameters not provided
        DECLARE @ActualBatchSize INT = ISNULL(@BatchSize, CAST(dbo.GetConfigValue(''Database.CleanupBatchSize'') AS INT));
        DECLARE @ActualOlderThanHours INT = ISNULL(@OlderThanHours, 24);
        
        DECLARE @CutoffTime DATETIME2(7) = DATEADD(HOUR, -@ActualOlderThanHours, GETUTCDATE());
        DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
        DECLARE @TotalExpired INT = 0;
        DECLARE @TotalDeleted INT = 0;
        DECLARE @BatchProcessed INT = 1;
        DECLARE @MaxBatches INT = 100; -- Prevent runaway cleanup
        DECLARE @BatchCount INT = 0;

        BEGIN TRY
            -- Phase 1: Mark expired contexts as expired
            WHILE @BatchProcessed > 0 AND @BatchCount < @MaxBatches
            BEGIN
                UPDATE TOP (@ActualBatchSize) dbo.AuthenticationContexts
                SET ContextState = ''expired'',
                    IsActive = 0,
                    UpdatedAt = @CurrentTime
                WHERE ExpiresAt < @CurrentTime
                  AND IsActive = 1
                  AND IsDeleted = 0;

                SET @BatchProcessed = @@ROWCOUNT;
                SET @TotalExpired = @TotalExpired + @BatchProcessed;
                SET @BatchCount = @BatchCount + 1;
                
                -- Brief pause to avoid blocking
                IF @BatchProcessed > 0
                    WAITFOR DELAY ''00:00:00.100''; -- 100ms pause
            END

            -- Phase 2: Soft delete old expired contexts
            SET @BatchProcessed = 1;
            SET @BatchCount = 0;
            
            WHILE @BatchProcessed > 0 AND @BatchCount < @MaxBatches
            BEGIN
                UPDATE TOP (@ActualBatchSize) dbo.AuthenticationContexts
                SET IsDeleted = 1,
                    UpdatedAt = @CurrentTime
                WHERE ExpiresAt < @CutoffTime
                  AND IsDeleted = 0;

                SET @BatchProcessed = @@ROWCOUNT;
                SET @TotalDeleted = @TotalDeleted + @BatchProcessed;
                SET @BatchCount = @BatchCount + 1;
                
                IF @BatchProcessed > 0
                    WAITFOR DELAY ''00:00:00.100'';
            END

            -- Log cleanup audit event
            EXEC dbo.LogAuditEvent
                @EventType = ''CONTEXT_CLEANUP'',
                @Details = CONCAT(''Cleanup completed: '', @TotalExpired, '' expired, '', @TotalDeleted, '' deleted''),
                @Success = 1;

        END TRY
        BEGIN CATCH
            DECLARE @ErrorMsg NVARCHAR(255) = ERROR_MESSAGE();
            
            EXEC dbo.LogError
                @ErrorMessage = @ErrorMsg,
                @ErrorSeverity = ''ERROR'',
                @AdditionalInfo = CONCAT(''BatchSize='', @ActualBatchSize, '', OlderThanHours='', @ActualOlderThanHours);
                
            SELECT 0 AS TotalCleaned, @ErrorMsg AS Message;
            RETURN;
        END CATCH
        
        -- Log performance metrics
        DECLARE @ExecutionTimeMs INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
        DECLARE @TotalProcessed INT = @TotalExpired + @TotalDeleted;
        
        EXEC dbo.LogPerformanceMetric
            @MetricName = ''CleanupExpiredContexts'',
            @MetricValue = @ExecutionTimeMs,
            @MetricUnit = ''milliseconds'',
            @AdditionalData = CONCAT(''Processed:'', @TotalProcessed, '', Expired:'', @TotalExpired, '', Deleted:'', @TotalDeleted);

        SELECT @TotalProcessed AS TotalCleaned, 
               CONCAT(''Cleanup completed: '', @TotalExpired, '' expired, '', @TotalDeleted, '' deleted'') AS Message;
    END;
    ');
    
    PRINT '✓ Cleanup and maintenance procedures created';
    
    -- ============================================================================
    -- CONFIGURATION VALUES
    -- ============================================================================
    
    PRINT 'Adding authentication-specific configuration values...';
    
    -- Add configuration values if they don''t exist
    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Audit.LogValidations')
        INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
        VALUES ('Audit.LogValidations', '0', 'bool', 'Enable detailed validation logging (high frequency)', 'Compliance');

    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Authentication.MaxSessionsPerUser')
        INSERT INTO dbo.SystemConfiguration (ConfigKey, ConfigValue, DataType, Description, Category) 
        VALUES ('Authentication.MaxSessionsPerUser', '5', 'int', 'Maximum concurrent sessions per user', 'Security');
    
    PRINT '✓ Configuration values added';
    
    -- ============================================================================
    -- PROCEDURE VALIDATION
    -- ============================================================================
    
    PRINT 'Validating authentication procedures...';
    
    DECLARE @ProcedureCount INT;
    SELECT @ProcedureCount = COUNT(*)
    FROM sys.procedures p
    INNER JOIN sys.schemas s ON p.schema_id = s.schema_id
    WHERE s.name = 'dbo' 
    AND p.name IN (
        'CreateAuthenticationContext', 'ValidateAuthenticationContext',
        'RefreshAuthenticationContext', 'InvalidateAuthenticationContext',
        'InvalidateAllContextsForMobile', 'UpdateAuthenticationState',
        'GetAuthenticationState', 'CleanupExpiredContexts'
    );
    
    IF @ProcedureCount = 8
        PRINT '✓ All 8 authentication procedures created successfully';
    ELSE
    BEGIN
        DECLARE @ErrorMsg NVARCHAR(255) = 'Expected 8 procedures, but found ' + CAST(@ProcedureCount AS NVARCHAR(10));
        RAISERROR(@ErrorMsg, 16, 1);
    END
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = @ProcedureCount
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 4.1: Authentication Procedures Completed Successfully';
    PRINT 'Procedures created: ' + CAST(@ProcedureCount AS NVARCHAR(10));
    PRINT 'Features: Context management, validation, state tracking, cleanup';
    PRINT 'Security: Enhanced audit trail, circuit breakers, rate limiting';
    PRINT 'Next: Layer 4.2 - Membership Procedures';
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
    PRINT 'ERROR in Layer 4.1: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO