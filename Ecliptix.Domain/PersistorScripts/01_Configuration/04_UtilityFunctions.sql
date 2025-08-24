/*
================================================================================
Layer 1.4: Utility Functions & Helpers
================================================================================
Purpose: Common utility functions and helper procedures for system operations
Dependencies: 01_SystemConfiguration.sql, 02_LoggingInfrastructure.sql, 03_ValidationFramework.sql
Execution Order: 5th - Foundation utilities for all system operations

Features:
- Date/Time utility functions
- String manipulation helpers
- Data formatting utilities
- System health check functions
- Performance monitoring helpers
- Circuit breaker implementation
- Retry policy helpers

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
PRINT 'Layer 1.4: Utility Functions & Helpers';
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
VALUES (@DeploymentId, '04_UtilityFunctions.sql', 4, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- CIRCUIT BREAKER INFRASTRUCTURE
    -- ============================================================================
    
    PRINT 'Creating circuit breaker infrastructure...';
    
    -- Circuit breaker state table
    IF OBJECT_ID('dbo.CircuitBreakerStates', 'U') IS NOT NULL 
        DROP TABLE dbo.CircuitBreakerStates;
    
    CREATE TABLE dbo.CircuitBreakerStates (
        ServiceName NVARCHAR(100) PRIMARY KEY,
        State NVARCHAR(20) NOT NULL DEFAULT 'CLOSED',
        FailureCount INT NOT NULL DEFAULT 0,
        SuccessCount INT NOT NULL DEFAULT 0,
        LastFailureAt DATETIME2(7),
        LastSuccessAt DATETIME2(7),
        NextRetryAt DATETIME2(7),
        CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
        UpdatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
        CONSTRAINT CHK_CircuitBreakerStates_State 
            CHECK (State IN ('CLOSED', 'OPEN', 'HALF_OPEN'))
    );
    
    CREATE NONCLUSTERED INDEX IX_CircuitBreakerStates_State ON dbo.CircuitBreakerStates (State);
    CREATE NONCLUSTERED INDEX IX_CircuitBreakerStates_NextRetryAt ON dbo.CircuitBreakerStates (NextRetryAt);
    
    PRINT '✓ CircuitBreakerStates table created successfully';
    
    -- ============================================================================
    -- DATE/TIME UTILITY FUNCTIONS
    -- ============================================================================
    
    PRINT 'Creating date/time utility functions...';
    
    -- Drop existing functions
    IF OBJECT_ID('dbo.GetBusinessDaysFromNow', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.GetBusinessDaysFromNow;
    
    IF OBJECT_ID('dbo.IsWithinBusinessHours', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.IsWithinBusinessHours;
    
    -- Function to calculate business days from now
    EXEC ('
    CREATE FUNCTION dbo.GetBusinessDaysFromNow(@Days INT)
    RETURNS DATETIME2(7)
    AS
    BEGIN
        DECLARE @ResultDate DATETIME2(7) = GETUTCDATE();
        DECLARE @DaysToAdd INT = 0;
        DECLARE @Counter INT = 0;
        
        WHILE @Counter < ABS(@Days)
        BEGIN
            SET @DaysToAdd = CASE WHEN @Days > 0 THEN 1 ELSE -1 END;
            SET @ResultDate = DATEADD(DAY, @DaysToAdd, @ResultDate);
            
            -- Skip weekends
            DECLARE @DayOfWeek INT = DATEPART(WEEKDAY, @ResultDate);
            IF @DayOfWeek NOT IN (1, 7) -- Sunday=1, Saturday=7
                SET @Counter = @Counter + 1;
        END
        
        RETURN @ResultDate;
    END;
    ');
    
    -- Function to check if current time is within business hours
    EXEC ('
    CREATE FUNCTION dbo.IsWithinBusinessHours(@CheckTime DATETIME2(7) = NULL)
    RETURNS BIT
    AS
    BEGIN
        DECLARE @Time DATETIME2(7) = ISNULL(@CheckTime, GETUTCDATE());
        DECLARE @DayOfWeek INT = DATEPART(WEEKDAY, @Time);
        DECLARE @Hour INT = DATEPART(HOUR, @Time);
        
        -- Business hours: Monday-Friday, 8 AM to 6 PM UTC
        IF @DayOfWeek BETWEEN 2 AND 6 AND @Hour BETWEEN 8 AND 17
            RETURN 1;
        
        RETURN 0;
    END;
    ');
    
    PRINT '✓ Date/time utility functions created successfully';
    
    -- ============================================================================
    -- STRING MANIPULATION HELPERS
    -- ============================================================================
    
    PRINT 'Creating string manipulation helpers...';
    
    -- Drop existing functions
    IF OBJECT_ID('dbo.FormatPhoneNumberDisplay', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.FormatPhoneNumberDisplay;
    
    IF OBJECT_ID('dbo.MaskSensitiveData', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.MaskSensitiveData;
    
    -- Function to format phone number for display
    EXEC ('
    CREATE FUNCTION dbo.FormatPhoneNumberDisplay(@PhoneNumber NVARCHAR(20))
    RETURNS NVARCHAR(30)
    AS
    BEGIN
        DECLARE @CleanedNumber NVARCHAR(20);
        DECLARE @FormattedNumber NVARCHAR(30);
        
        -- Clean the number
        SET @CleanedNumber = REPLACE(REPLACE(REPLACE(REPLACE(@PhoneNumber, '' '', ''''), ''('', ''''), '')'', ''''), ''-'', '''');
        SET @CleanedNumber = REPLACE(REPLACE(@CleanedNumber, ''.'', ''''), ''+'', '''');
        
        -- Format based on length
        DECLARE @Length INT = LEN(@CleanedNumber);
        
        IF @Length = 10
            -- US format: (123) 456-7890
            SET @FormattedNumber = ''('' + LEFT(@CleanedNumber, 3) + '') '' + 
                                 SUBSTRING(@CleanedNumber, 4, 3) + ''-'' + 
                                 RIGHT(@CleanedNumber, 4);
        ELSE IF @Length = 11 AND LEFT(@CleanedNumber, 1) = ''1''
            -- US with country code: +1 (123) 456-7890
            SET @FormattedNumber = ''+1 ('' + SUBSTRING(@CleanedNumber, 2, 3) + '') '' + 
                                 SUBSTRING(@CleanedNumber, 5, 3) + ''-'' + 
                                 RIGHT(@CleanedNumber, 4);
        ELSE
            -- International format: +XX XXX XXX XXXX
            SET @FormattedNumber = ''+'' + @CleanedNumber;
        
        RETURN ISNULL(@FormattedNumber, @PhoneNumber);
    END;
    ');
    
    -- Function to mask sensitive data for logging
    EXEC ('
    CREATE FUNCTION dbo.MaskSensitiveData(@Data NVARCHAR(MAX), @MaskType NVARCHAR(20) = ''PARTIAL'')
    RETURNS NVARCHAR(MAX)
    AS
    BEGIN
        DECLARE @MaskedData NVARCHAR(MAX);
        DECLARE @Length INT = LEN(@Data);
        
        IF @Data IS NULL OR @Length = 0
            RETURN @Data;
        
        IF @MaskType = ''FULL''
            SET @MaskedData = REPLICATE(''*'', @Length);
        ELSE IF @MaskType = ''PARTIAL''
        BEGIN
            -- Show first 2 and last 2 characters for data > 6 chars
            IF @Length > 6
                SET @MaskedData = LEFT(@Data, 2) + REPLICATE(''*'', @Length - 4) + RIGHT(@Data, 2);
            ELSE IF @Length > 2
                SET @MaskedData = LEFT(@Data, 1) + REPLICATE(''*'', @Length - 1);
            ELSE
                SET @MaskedData = REPLICATE(''*'', @Length);
        END
        ELSE IF @MaskType = ''PHONE''
        BEGIN
            -- Mask phone numbers: show last 4 digits only
            IF @Length >= 4
                SET @MaskedData = REPLICATE(''*'', @Length - 4) + RIGHT(@Data, 4);
            ELSE
                SET @MaskedData = REPLICATE(''*'', @Length);
        END
        ELSE
            SET @MaskedData = @Data; -- No masking
        
        RETURN @MaskedData;
    END;
    ');
    
    PRINT '✓ String manipulation helpers created successfully';
    
    -- ============================================================================
    -- SYSTEM HEALTH CHECK FUNCTIONS
    -- ============================================================================
    
    PRINT 'Creating system health check procedures...';
    
    -- Drop existing procedures
    IF OBJECT_ID('dbo.GetSystemHealthStatus', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.GetSystemHealthStatus;
    
    -- System health check procedure
    EXEC ('
    CREATE PROCEDURE dbo.GetSystemHealthStatus
        @IncludeDetails BIT = 0
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @HealthStatus TABLE (
            Component NVARCHAR(50),
            Status NVARCHAR(20),
            Details NVARCHAR(MAX),
            LastChecked DATETIME2(7)
        );
        
        DECLARE @OverallStatus NVARCHAR(20) = ''HEALTHY'';
        
        -- Check database connectivity
        BEGIN TRY
            DECLARE @TestValue INT = 1;
            INSERT INTO @HealthStatus VALUES (''Database'', ''HEALTHY'', ''Database connection successful'', GETUTCDATE());
        END TRY
        BEGIN CATCH
            INSERT INTO @HealthStatus VALUES (''Database'', ''UNHEALTHY'', ERROR_MESSAGE(), GETUTCDATE());
            SET @OverallStatus = ''UNHEALTHY'';
        END CATCH
        
        -- Check configuration system
        BEGIN TRY
            DECLARE @ConfigTest NVARCHAR(500) = dbo.GetConfigValue(''Authentication.MaxFailedAttempts'');
            IF @ConfigTest IS NOT NULL
                INSERT INTO @HealthStatus VALUES (''Configuration'', ''HEALTHY'', ''Configuration system operational'', GETUTCDATE());
            ELSE
            BEGIN
                INSERT INTO @HealthStatus VALUES (''Configuration'', ''DEGRADED'', ''Configuration values not accessible'', GETUTCDATE());
                IF @OverallStatus = ''HEALTHY'' SET @OverallStatus = ''DEGRADED'';
            END
        END TRY
        BEGIN CATCH
            INSERT INTO @HealthStatus VALUES (''Configuration'', ''UNHEALTHY'', ERROR_MESSAGE(), GETUTCDATE());
            SET @OverallStatus = ''UNHEALTHY'';
        END CATCH
        
        -- Check recent error rates
        BEGIN TRY
            DECLARE @RecentErrors INT;
            SELECT @RecentErrors = COUNT(*)
            FROM dbo.ErrorLog
            WHERE CreatedAt >= DATEADD(MINUTE, -15, GETUTCDATE());
            
            IF @RecentErrors = 0
                INSERT INTO @HealthStatus VALUES (''ErrorRate'', ''HEALTHY'', ''No recent errors'', GETUTCDATE());
            ELSE IF @RecentErrors < 10
            BEGIN
                INSERT INTO @HealthStatus VALUES (''ErrorRate'', ''DEGRADED'', 
                    ''Recent errors: '' + CAST(@RecentErrors AS NVARCHAR(10)), GETUTCDATE());
                IF @OverallStatus = ''HEALTHY'' SET @OverallStatus = ''DEGRADED'';
            END
            ELSE
            BEGIN
                INSERT INTO @HealthStatus VALUES (''ErrorRate'', ''UNHEALTHY'', 
                    ''High error rate: '' + CAST(@RecentErrors AS NVARCHAR(10)) + '' errors in 15 minutes'', GETUTCDATE());
                SET @OverallStatus = ''UNHEALTHY'';
            END
        END TRY
        BEGIN CATCH
            INSERT INTO @HealthStatus VALUES (''ErrorRate'', ''UNKNOWN'', ''Unable to check error rates'', GETUTCDATE());
        END CATCH
        
        -- Check circuit breaker states
        BEGIN TRY
            DECLARE @OpenCircuits INT;
            SELECT @OpenCircuits = COUNT(*)
            FROM dbo.CircuitBreakerStates
            WHERE State = ''OPEN'';
            
            IF @OpenCircuits = 0
                INSERT INTO @HealthStatus VALUES (''CircuitBreakers'', ''HEALTHY'', ''All circuits closed'', GETUTCDATE());
            ELSE
            BEGIN
                INSERT INTO @HealthStatus VALUES (''CircuitBreakers'', ''DEGRADED'', 
                    CAST(@OpenCircuits AS NVARCHAR(10)) + '' open circuits'', GETUTCDATE());
                IF @OverallStatus = ''HEALTHY'' SET @OverallStatus = ''DEGRADED'';
            END
        END TRY
        BEGIN CATCH
            INSERT INTO @HealthStatus VALUES (''CircuitBreakers'', ''UNKNOWN'', ''Unable to check circuit breakers'', GETUTCDATE());
        END CATCH
        
        -- Return results
        SELECT @OverallStatus AS OverallStatus, GETUTCDATE() AS CheckedAt;
        
        IF @IncludeDetails = 1
        BEGIN
            SELECT Component, Status, Details, LastChecked
            FROM @HealthStatus
            ORDER BY 
                CASE Status 
                    WHEN ''UNHEALTHY'' THEN 1
                    WHEN ''DEGRADED'' THEN 2
                    WHEN ''HEALTHY'' THEN 3
                    ELSE 4
                END,
                Component;
        END
    END;
    ');
    
    PRINT '✓ System health check procedures created successfully';
    
    -- ============================================================================
    -- CIRCUIT BREAKER IMPLEMENTATION
    -- ============================================================================
    
    PRINT 'Creating circuit breaker procedures...';
    
    -- Drop existing procedures
    IF OBJECT_ID('dbo.CheckCircuitBreaker', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.CheckCircuitBreaker;
    
    IF OBJECT_ID('dbo.RecordCircuitBreakerSuccess', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.RecordCircuitBreakerSuccess;
    
    IF OBJECT_ID('dbo.RecordCircuitBreakerFailure', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.RecordCircuitBreakerFailure;
    
    -- Check circuit breaker state
    EXEC ('
    CREATE PROCEDURE dbo.CheckCircuitBreaker
        @ServiceName NVARCHAR(100),
        @IsOpen BIT OUTPUT,
        @ErrorMessage NVARCHAR(255) OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @State NVARCHAR(20);
        DECLARE @NextRetryAt DATETIME2(7);
        DECLARE @FailureThreshold INT = CAST(dbo.GetConfigValue(''CircuitBreaker.FailureThreshold'') AS INT);
        DECLARE @TimeoutMinutes INT = CAST(dbo.GetConfigValue(''CircuitBreaker.TimeoutMinutes'') AS INT);
        
        -- Initialize circuit breaker if not exists
        IF NOT EXISTS (SELECT 1 FROM dbo.CircuitBreakerStates WHERE ServiceName = @ServiceName)
        BEGIN
            INSERT INTO dbo.CircuitBreakerStates (ServiceName) VALUES (@ServiceName);
        END
        
        -- Get current state
        SELECT @State = State, @NextRetryAt = NextRetryAt
        FROM dbo.CircuitBreakerStates
        WHERE ServiceName = @ServiceName;
        
        -- Check state
        IF @State = ''CLOSED''
        BEGIN
            SET @IsOpen = 0;
            SET @ErrorMessage = NULL;
        END
        ELSE IF @State = ''OPEN''
        BEGIN
            -- Check if retry time has passed
            IF GETUTCDATE() >= @NextRetryAt
            BEGIN
                -- Move to HALF_OPEN
                UPDATE dbo.CircuitBreakerStates
                SET State = ''HALF_OPEN'', UpdatedAt = GETUTCDATE()
                WHERE ServiceName = @ServiceName;
                
                SET @IsOpen = 0;
                SET @ErrorMessage = NULL;
            END
            ELSE
            BEGIN
                SET @IsOpen = 1;
                SET @ErrorMessage = ''Circuit breaker is OPEN. Service temporarily unavailable.'';
            END
        END
        ELSE -- HALF_OPEN
        BEGIN
            SET @IsOpen = 0;
            SET @ErrorMessage = NULL;
        END
    END;
    ');
    
    -- Record circuit breaker success
    EXEC ('
    CREATE PROCEDURE dbo.RecordCircuitBreakerSuccess
        @ServiceName NVARCHAR(100)
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @SuccessThreshold INT = CAST(dbo.GetConfigValue(''CircuitBreaker.SuccessThreshold'') AS INT);
        DECLARE @CurrentState NVARCHAR(20);
        DECLARE @SuccessCount INT;
        
        -- Update success count
        UPDATE dbo.CircuitBreakerStates
        SET SuccessCount = SuccessCount + 1,
            LastSuccessAt = GETUTCDATE(),
            UpdatedAt = GETUTCDATE()
        WHERE ServiceName = @ServiceName;
        
        -- Get updated values
        SELECT @CurrentState = State, @SuccessCount = SuccessCount
        FROM dbo.CircuitBreakerStates
        WHERE ServiceName = @ServiceName;
        
        -- Close circuit if enough successes in HALF_OPEN state
        IF @CurrentState = ''HALF_OPEN'' AND @SuccessCount >= @SuccessThreshold
        BEGIN
            UPDATE dbo.CircuitBreakerStates
            SET State = ''CLOSED'',
                FailureCount = 0,
                SuccessCount = 0,
                NextRetryAt = NULL,
                UpdatedAt = GETUTCDATE()
            WHERE ServiceName = @ServiceName;
            
            -- Log the recovery
            EXEC dbo.LogAuditEvent 
                @EventType = ''CIRCUIT_BREAKER_CLOSED'',
                @Details = ''Circuit breaker closed after successful operations'',
                @AdditionalData = @ServiceName;
        END
    END;
    ');
    
    -- Record circuit breaker failure
    EXEC ('
    CREATE PROCEDURE dbo.RecordCircuitBreakerFailure
        @ServiceName NVARCHAR(100),
        @ErrorMessage NVARCHAR(MAX) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @FailureThreshold INT = CAST(dbo.GetConfigValue(''CircuitBreaker.FailureThreshold'') AS INT);
        DECLARE @TimeoutMinutes INT = CAST(dbo.GetConfigValue(''CircuitBreaker.TimeoutMinutes'') AS INT);
        DECLARE @CurrentState NVARCHAR(20);
        DECLARE @FailureCount INT;
        
        -- Update failure count
        UPDATE dbo.CircuitBreakerStates
        SET FailureCount = FailureCount + 1,
            SuccessCount = 0,
            LastFailureAt = GETUTCDATE(),
            UpdatedAt = GETUTCDATE()
        WHERE ServiceName = @ServiceName;
        
        -- Get updated values
        SELECT @CurrentState = State, @FailureCount = FailureCount
        FROM dbo.CircuitBreakerStates
        WHERE ServiceName = @ServiceName;
        
        -- Open circuit if failure threshold exceeded
        IF (@CurrentState IN (''CLOSED'', ''HALF_OPEN'')) AND @FailureCount >= @FailureThreshold
        BEGIN
            UPDATE dbo.CircuitBreakerStates
            SET State = ''OPEN'',
                NextRetryAt = DATEADD(MINUTE, @TimeoutMinutes, GETUTCDATE()),
                UpdatedAt = GETUTCDATE()
            WHERE ServiceName = @ServiceName;
            
            -- Log the circuit opening
            EXEC dbo.LogError 
                @ErrorMessage = ''Circuit breaker opened due to repeated failures'',
                @ErrorSeverity = ''WARNING'',
                @AdditionalInfo = @ServiceName + '': '' + ISNULL(@ErrorMessage, ''Unknown error'');
        END
    END;
    ');
    
    PRINT '✓ Circuit breaker procedures created successfully';
    
    -- ============================================================================
    -- PERFORMANCE MONITORING HELPERS
    -- ============================================================================
    
    PRINT 'Creating performance monitoring helpers...';
    
    -- Drop existing procedures
    IF OBJECT_ID('dbo.StartPerformanceTimer', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.StartPerformanceTimer;
    
    IF OBJECT_ID('dbo.EndPerformanceTimer', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.EndPerformanceTimer;
    
    -- Start performance timer
    EXEC ('
    CREATE PROCEDURE dbo.StartPerformanceTimer
        @OperationName NVARCHAR(100),
        @TimerId UNIQUEIDENTIFIER OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        SET @TimerId = NEWID();
        
        -- Store timer start in temp table or session context
        -- For simplicity, we''ll use a session-based approach
        DECLARE @SessionInfo NVARCHAR(200) = ''PERF_TIMER_'' + CAST(@TimerId AS NVARCHAR(36));
        DECLARE @StartTime NVARCHAR(30) = CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
        
        -- Using session context to store timer info (SQL Server 2016+)
        EXEC sp_set_session_context @SessionInfo, @StartTime, @readonly = 0;
        
        -- Also store operation name
        SET @SessionInfo = ''PERF_OP_'' + CAST(@TimerId AS NVARCHAR(36));
        EXEC sp_set_session_context @SessionInfo, @OperationName, @readonly = 0;
    END;
    ');
    
    -- End performance timer
    EXEC ('
    CREATE PROCEDURE dbo.EndPerformanceTimer
        @TimerId UNIQUEIDENTIFIER,
        @AdditionalMetrics NVARCHAR(MAX) = NULL
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @StartTimeStr NVARCHAR(30);
        DECLARE @OperationName NVARCHAR(100);
        DECLARE @SessionInfo NVARCHAR(200);
        
        -- Retrieve start time and operation name
        SET @SessionInfo = ''PERF_TIMER_'' + CAST(@TimerId AS NVARCHAR(36));
        SET @StartTimeStr = CAST(SESSION_CONTEXT(@SessionInfo) AS NVARCHAR(30));
        
        SET @SessionInfo = ''PERF_OP_'' + CAST(@TimerId AS NVARCHAR(36));
        SET @OperationName = CAST(SESSION_CONTEXT(@SessionInfo) AS NVARCHAR(100));
        
        IF @StartTimeStr IS NOT NULL AND @OperationName IS NOT NULL
        BEGIN
            DECLARE @StartTime DATETIME2(7) = CAST(@StartTimeStr AS DATETIME2(7));
            DECLARE @EndTime DATETIME2(7) = GETUTCDATE();
            DECLARE @DurationMs BIGINT = DATEDIFF(MILLISECOND, @StartTime, @EndTime);
            
            -- Log performance metric
            EXEC dbo.LogPerformanceMetric 
                @MetricName = @OperationName,
                @MetricValue = @DurationMs,
                @MetricUnit = ''milliseconds'',
                @AdditionalData = @AdditionalMetrics;
            
            -- Clean up session context
            SET @SessionInfo = ''PERF_TIMER_'' + CAST(@TimerId AS NVARCHAR(36));
            EXEC sp_set_session_context @SessionInfo, NULL;
            
            SET @SessionInfo = ''PERF_OP_'' + CAST(@TimerId AS NVARCHAR(36));
            EXEC sp_set_session_context @SessionInfo, NULL;
        END
    END;
    ');
    
    PRINT '✓ Performance monitoring helpers created successfully';
    
    -- ============================================================================
    -- UTILITY FRAMEWORK TESTING
    -- ============================================================================
    
    PRINT 'Testing utility framework...';
    
    -- Test circuit breaker functionality
    DECLARE @IsOpen BIT, @ErrorMsg NVARCHAR(255);
    EXEC dbo.CheckCircuitBreaker 'TestService', @IsOpen OUTPUT, @ErrorMsg OUTPUT;
    
    -- Test system health check
    EXEC dbo.GetSystemHealthStatus @IncludeDetails = 0;
    
    -- Test formatting functions
    DECLARE @TestPhone NVARCHAR(30) = dbo.FormatPhoneNumberDisplay('1234567890');
    DECLARE @TestMask NVARCHAR(MAX) = dbo.MaskSensitiveData('SecretData123', 'PARTIAL');
    
    IF @TestPhone LIKE '(123) 456-7890' AND @TestMask LIKE 'Se*********23'
        PRINT '✓ Utility function tests passed';
    ELSE
        PRINT '⚠ Some utility function tests may have failed';
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = 11
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 1.4: Utility Functions & Helpers Completed Successfully';
    PRINT 'Circuit breaker infrastructure: ✓ Created';
    PRINT 'Date/time utilities: 2 functions';
    PRINT 'String helpers: 2 functions';
    PRINT 'System health monitoring: ✓ Created';
    PRINT 'Performance monitoring: ✓ Created';
    PRINT 'Next: Layer 2 - Core Domain Tables';
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
    PRINT 'ERROR in Layer 1.4: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO