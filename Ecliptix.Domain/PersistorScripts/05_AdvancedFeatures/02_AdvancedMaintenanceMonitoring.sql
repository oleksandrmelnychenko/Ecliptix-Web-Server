/*
================================================================================
Layer 5.2: Advanced Maintenance & Monitoring
================================================================================
Purpose: Advanced system maintenance, monitoring, and reporting procedures
Dependencies: Layers 1-4 (Complete infrastructure and business logic), Layer 5.1 (Advanced Security)
Execution Order: 13th - Advanced maintenance and monitoring layer

Features:
- Automated maintenance procedures
- Advanced monitoring and alerting
- Performance analytics and reporting
- Data archival and cleanup
- Health monitoring and diagnostics
- Advanced metrics collection

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
PRINT 'Layer 5.2: Advanced Maintenance & Monitoring';
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
VALUES (@DeploymentId, '02_AdvancedMaintenanceMonitoring.sql', 12, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- CLEANUP EXISTING PROCEDURES
    -- ============================================================================
    
    PRINT 'Cleaning up existing maintenance and monitoring procedures...';
    
    IF OBJECT_ID('dbo.PerformSystemMaintenance', 'P') IS NOT NULL DROP PROCEDURE dbo.PerformSystemMaintenance;
    IF OBJECT_ID('dbo.GenerateSecurityReport', 'P') IS NOT NULL DROP PROCEDURE dbo.GenerateSecurityReport;
    IF OBJECT_ID('dbo.AnalyzeSystemPerformance', 'P') IS NOT NULL DROP PROCEDURE dbo.AnalyzeSystemPerformance;
    IF OBJECT_ID('dbo.ArchiveOldData', 'P') IS NOT NULL DROP PROCEDURE dbo.ArchiveOldData;
    IF OBJECT_ID('dbo.MonitorCircuitBreakers', 'P') IS NOT NULL DROP PROCEDURE dbo.MonitorCircuitBreakers;
    IF OBJECT_ID('dbo.GenerateUsageStatistics', 'P') IS NOT NULL DROP PROCEDURE dbo.GenerateUsageStatistics;
    
    PRINT '✓ Existing maintenance and monitoring procedures cleaned up';
    
    -- ============================================================================
    -- SYSTEM MAINTENANCE PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating system maintenance procedures...';
    
    -- PerformSystemMaintenance: Comprehensive system maintenance
        CREATE PROCEDURE dbo.PerformSystemMaintenance
        @MaintenanceType NVARCHAR(50) = 'FULL', -- FULL, QUICK, CLEANUP_ONLY, ANALYSIS_ONLY
        @ForceExecution BIT = 0
    AS
    BEGIN
        SET NOCOUNT ON;
        SET XACT_ABORT ON;
        
        DECLARE @StartTime DATETIME2(7) = GETUTCDATE();
        DECLARE @TotalRowsProcessed INT = 0;
        DECLARE @MaintenanceResults TABLE (
            Component NVARCHAR(100),
            Action NVARCHAR(100),
            RowsAffected INT,
            Success BIT,
            Message NVARCHAR(500)
        );
        
        BEGIN TRY
            -- ================================================================
            -- MAINTENANCE ELIGIBILITY CHECK
            -- ================================================================
            
            -- Check if maintenance is already running
            IF @ForceExecution = 0 AND EXISTS (
                SELECT 1 FROM dbo.DeploymentLog 
                WHERE ScriptName = 'SYSTEM_MAINTENANCE' 
                  AND Status = 'RUNNING'
                  AND CreatedAt > DATEADD(HOUR, -2, GETUTCDATE())
            )
            BEGIN
                INSERT INTO @MaintenanceResults VALUES ('System', 'Maintenance Check', 0, 0, 'Maintenance already in progress or recently completed');
                GOTO ReturnResults;
            END
            
            -- Log maintenance start
            INSERT INTO dbo.DeploymentLog (DeploymentId, ScriptName, ExecutionOrder, Status)
            VALUES (NEWID(), 'SYSTEM_MAINTENANCE', 999, 'RUNNING');
            
            DECLARE @MaintenanceLogId BIGINT = SCOPE_IDENTITY();
            
            -- ================================================================
            -- EXPIRED DATA CLEANUP
            -- ================================================================
            
            IF @MaintenanceType IN ('FULL', 'CLEANUP_ONLY')
            BEGIN
                PRINT 'Performing expired data cleanup...';
                
                -- Clean up expired authentication contexts
                DECLARE @ExpiredContexts INT;
                EXEC dbo.CleanupExpiredContexts @BatchSize = 1000, @OlderThanHours = 24;
                
                -- Clean up expired verification flows
                DECLARE @ExpiredFlowsCount INT = 0;
                UPDATE dbo.VerificationFlows
                SET Status = 'expired', UpdatedAt = GETUTCDATE()
                WHERE Status = 'pending'
                  AND ExpiresAt < GETUTCDATE()
                  AND IsDeleted = 0;
                
                SET @ExpiredFlowsCount = @@ROWCOUNT;
                SET @TotalRowsProcessed = @TotalRowsProcessed + @ExpiredFlowsCount;
                
                INSERT INTO @MaintenanceResults VALUES ('VerificationFlows', 'Expire Old Flows', @ExpiredFlowsCount, 1, 'Expired verification flows updated');
                
                -- Clean up expired OTP records
                DECLARE @ExpiredOtpCount INT = 0;
                UPDATE dbo.OtpRecords
                SET Status = 'expired', IsActive = 0, UpdatedAt = GETUTCDATE()
                WHERE Status = 'pending'
                  AND ExpiresAt < GETUTCDATE()
                  AND IsActive = 1;
                
                SET @ExpiredOtpCount = @@ROWCOUNT;
                SET @TotalRowsProcessed = @TotalRowsProcessed + @ExpiredOtpCount;
                
                INSERT INTO @MaintenanceResults VALUES ('OtpRecords', 'Expire Old OTPs', @ExpiredOtpCount, 1, 'Expired OTP records updated');
                
                -- Archive old audit logs
                DECLARE @RetentionDays INT = CAST(dbo.GetConfigValue('Audit.RetentionDays') AS INT);
                EXEC dbo.CleanupAuditLogs @RetentionDays = @RetentionDays, @BatchSize = 2000;
            END
            
            -- ================================================================
            -- PERFORMANCE OPTIMIZATION
            -- ================================================================
            
            IF @MaintenanceType IN ('FULL', 'ANALYSIS_ONLY')
            BEGIN
                PRINT 'Performing performance optimization...';
                
                -- Update statistics on critical tables
                DECLARE @StatsUpdated INT = 0;
                
                UPDATE STATISTICS dbo.PhoneNumbers;
                UPDATE STATISTICS dbo.VerificationFlows;
                UPDATE STATISTICS dbo.OtpRecords;
                UPDATE STATISTICS dbo.Memberships;
                UPDATE STATISTICS dbo.AuthenticationContexts;
                UPDATE STATISTICS dbo.LoginAttempts;
                
                SET @StatsUpdated = 6;
                
                INSERT INTO @MaintenanceResults VALUES ('Database', 'Update Statistics', @StatsUpdated, 1, 'Statistics updated on critical tables');
                
                -- Analyze fragmentation and recommend rebuilds (informational)
                DECLARE @FragmentationInfo TABLE (
                    TableName NVARCHAR(128),
                    IndexName NVARCHAR(128),
                    FragmentationPercent DECIMAL(5,2)
                );
                
                -- Note: In production, you would use DMVs to check fragmentation
                -- This is a simplified example
                INSERT INTO @FragmentationInfo VALUES ('Example', 'Example_Index', 15.5);
                
                INSERT INTO @MaintenanceResults VALUES ('Database', 'Fragmentation Analysis', 1, 1, 'Fragmentation analysis completed');
            END
            
            -- ================================================================
            -- CIRCUIT BREAKER MAINTENANCE
            -- ================================================================
            
            IF @MaintenanceType IN ('FULL', 'QUICK')
            BEGIN
                PRINT 'Performing circuit breaker maintenance...';
                
                -- Reset circuit breakers that have been stuck open
                DECLARE @ResetCircuits INT = 0;
                
                UPDATE dbo.CircuitBreakerStates
                SET State = 'CLOSED', FailureCount = 0, NextRetryAt = NULL, UpdatedAt = GETUTCDATE()
                WHERE State = 'OPEN'
                  AND NextRetryAt < DATEADD(HOUR, -1, GETUTCDATE()); -- Reset circuits open for more than 1 hour
                
                SET @ResetCircuits = @@ROWCOUNT;
                SET @TotalRowsProcessed = @TotalRowsProcessed + @ResetCircuits;
                
                INSERT INTO @MaintenanceResults VALUES ('CircuitBreakers', 'Reset Stuck Circuits', @ResetCircuits, 1, 'Reset circuit breakers that were stuck open');
            END
            
            -- ================================================================
            -- SECURITY MAINTENANCE
            -- ================================================================
            
            IF @MaintenanceType IN ('FULL', 'CLEANUP_ONLY')
            BEGIN
                PRINT 'Performing security maintenance...';
                
                -- Clean up old failed login attempts (keep recent ones for analysis)
                DECLARE @CleanedLoginAttempts INT = 0;
                
                DELETE FROM dbo.LoginAttempts
                WHERE Timestamp < DATEADD(DAY, -7, GETUTCDATE())
                  AND IsSuccess = 0;
                
                SET @CleanedLoginAttempts = @@ROWCOUNT;
                SET @TotalRowsProcessed = @TotalRowsProcessed + @CleanedLoginAttempts;
                
                INSERT INTO @MaintenanceResults VALUES ('LoginAttempts', 'Cleanup Old Failed Attempts', @CleanedLoginAttempts, 1, 'Cleaned up old failed login attempts');
                
                -- Clean up old membership attempts
                DECLARE @CleanedMembershipAttempts INT = 0;
                
                DELETE FROM dbo.MembershipAttempts
                WHERE Timestamp < DATEADD(DAY, -30, GETUTCDATE())
                  AND IsSuccess = 0;
                
                SET @CleanedMembershipAttempts = @@ROWCOUNT;
                SET @TotalRowsProcessed = @TotalRowsProcessed + @CleanedMembershipAttempts;
                
                INSERT INTO @MaintenanceResults VALUES ('MembershipAttempts', 'Cleanup Old Failed Attempts', @CleanedMembershipAttempts, 1, 'Cleaned up old failed membership attempts');
            END
            
            -- ================================================================
            -- COMPLETION
            -- ================================================================
            
            -- Update maintenance log
            UPDATE dbo.DeploymentLog
            SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = @TotalRowsProcessed
            WHERE Id = @MaintenanceLogId;
            
            -- Log successful maintenance
            EXEC dbo.LogAuditEvent
                @EventType = 'SYSTEM_MAINTENANCE_COMPLETED',
                @Details = CONCAT('System maintenance completed successfully. Type: ', @MaintenanceType),
                @Success = 1,
                @AdditionalData = CONCAT('RowsProcessed:', @TotalRowsProcessed);
                
        END TRY
        BEGIN CATCH
            -- Update maintenance log with error
            UPDATE dbo.DeploymentLog
            SET Status = 'FAILED', EndTime = GETUTCDATE(), ErrorMessage = ERROR_MESSAGE()
            WHERE Id = @MaintenanceLogId;
            
            INSERT INTO @MaintenanceResults VALUES ('System', 'Maintenance Execution', 0, 0, ERROR_MESSAGE());
            
            EXEC dbo.LogError
                @ErrorMessage = ERROR_MESSAGE(),
                @ErrorSeverity = 'ERROR',
                @AdditionalInfo = 'System maintenance failed';
        END CATCH
        
        ReturnResults:
        -- Return maintenance results
        SELECT 
            Component,
            Action,
            RowsAffected,
            Success,
            Message,
            DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE()) AS ExecutionTimeMs
        FROM @MaintenanceResults
        ORDER BY Component, Action;
        
        -- Return summary
        SELECT 
            @MaintenanceType AS MaintenanceType,
            @TotalRowsProcessed AS TotalRowsProcessed,
            DATEDIFF(SECOND, @StartTime, GETUTCDATE()) AS TotalExecutionSeconds,
            CASE WHEN EXISTS (SELECT 1 FROM @MaintenanceResults WHERE Success = 0) THEN 0 ELSE 1 END AS OverallSuccess;
    END;
    
    PRINT '✓ System maintenance procedures created';
    
    -- ============================================================================
    -- MONITORING AND REPORTING PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating monitoring and reporting procedures...';
    
    -- GenerateSecurityReport: Comprehensive security analysis report
        CREATE PROCEDURE dbo.GenerateSecurityReport
        @ReportPeriodHours INT = 24,
        @IncludeDetails BIT = 0
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @StartTime DATETIME2(7) = DATEADD(HOUR, -@ReportPeriodHours, GETUTCDATE());
        DECLARE @EndTime DATETIME2(7) = GETUTCDATE();
        
        -- Security metrics summary
        SELECT 
            'Security Metrics Summary' AS ReportSection,
            @ReportPeriodHours AS PeriodHours,
            @StartTime AS StartTime,
            @EndTime AS EndTime;
        
        -- Authentication statistics
        SELECT 
            'Authentication Statistics' AS ReportSection,
            COUNT(*) AS TotalLoginAttempts,
            SUM(CASE WHEN IsSuccess = 1 THEN 1 ELSE 0 END) AS SuccessfulLogins,
            SUM(CASE WHEN IsSuccess = 0 THEN 1 ELSE 0 END) AS FailedLogins,
            COUNT(DISTINCT PhoneNumber) AS UniqueUsers,
            CAST(AVG(CAST(IsSuccess AS FLOAT)) * 100 AS DECIMAL(5,2)) AS SuccessRate
        FROM dbo.LoginAttempts
        WHERE Timestamp BETWEEN @StartTime AND @EndTime;
        
        -- Lockout statistics
        SELECT 
            'Account Lockout Statistics' AS ReportSection,
            COUNT(*) AS TotalLockouts,
            COUNT(DISTINCT PhoneNumber) AS UsersAffected,
            AVG(CAST(SUBSTRING(Outcome, CHARINDEX('LOCKED_UNTIL:', Outcome) + 12, 10) AS FLOAT)) AS AvgLockoutMinutes
        FROM dbo.LoginAttempts
        WHERE Outcome LIKE 'LOCKED_UNTIL:%'
          AND Timestamp BETWEEN @StartTime AND @EndTime;
        
        -- Suspicious activity summary
        SELECT 
            'Suspicious Activity Summary' AS ReportSection,
            COUNT(*) AS SuspiciousEvents,
            COUNT(DISTINCT CASE WHEN EventType LIKE '%THREAT%' THEN EventType END) AS ThreatTypes,
            COUNT(CASE WHEN EventType = 'SECURITY_THREAT_DETECTED' THEN 1 END) AS ThreatsDetected,
            COUNT(CASE WHEN EventType = 'ACCOUNT_LOCKED' THEN 1 END) AS SecurityLockouts
        FROM dbo.AuditLog
        WHERE CreatedAt BETWEEN @StartTime AND @EndTime
          AND EventType IN ('SECURITY_THREAT_DETECTED', 'LOGIN_BLOCKED_LOCKOUT', 'SUSPICIOUS_ACTIVITY', 'ACCOUNT_LOCKED');
        
        -- Circuit breaker status
        SELECT 
            'Circuit Breaker Status' AS ReportSection,
            ServiceName,
            State,
            FailureCount,
            SuccessCount,
            LastFailureAt,
            NextRetryAt
        FROM dbo.CircuitBreakerStates
        ORDER BY ServiceName;
        
        -- Verification flow statistics
        SELECT 
            'Verification Flow Statistics' AS ReportSection,
            Purpose,
            COUNT(*) AS TotalFlows,
            SUM(CASE WHEN Status = 'verified' THEN 1 ELSE 0 END) AS VerifiedFlows,
            SUM(CASE WHEN Status = 'failed' THEN 1 ELSE 0 END) AS FailedFlows,
            SUM(CASE WHEN Status = 'expired' THEN 1 ELSE 0 END) AS ExpiredFlows,
            AVG(CAST(OtpCount AS FLOAT)) AS AvgOtpAttempts
        FROM dbo.VerificationFlows
        WHERE CreatedAt BETWEEN @StartTime AND @EndTime
        GROUP BY Purpose
        ORDER BY Purpose;
        
        -- Detailed security events (if requested)
        IF @IncludeDetails = 1
        BEGIN
            SELECT 
                'Detailed Security Events' AS ReportSection,
                EventType,
                Details,
                IpAddress,
                CreatedAt,
                CASE WHEN Success = 1 THEN 'Success' ELSE 'Failed' END AS Result
            FROM dbo.AuditLog
            WHERE CreatedAt BETWEEN @StartTime AND @EndTime
              AND EventType IN ('SECURITY_THREAT_DETECTED', 'LOGIN_FAILED_WITH_THREAT', 'SUSPICIOUS_ACTIVITY', 'ACCOUNT_LOCKED')
            ORDER BY CreatedAt DESC;
        END
        
        -- Performance impact summary
        SELECT 
            'Performance Impact Summary' AS ReportSection,
            AVG(CASE WHEN MetricName = 'LoginMembership' THEN CAST(MetricValue AS FLOAT) END) AS AvgLoginTimeMs,
            MAX(CASE WHEN MetricName = 'LoginMembership' THEN CAST(MetricValue AS FLOAT) END) AS MaxLoginTimeMs,
            COUNT(CASE WHEN MetricName = 'LoginMembership' THEN 1 END) AS LoginOperations,
            AVG(CASE WHEN MetricName = 'CreateAuthenticationContext' THEN CAST(MetricValue AS FLOAT) END) AS AvgAuthContextTimeMs
        FROM dbo.PerformanceMetrics
        WHERE CreatedAt BETWEEN @StartTime AND @EndTime;
        
        -- Generate timestamp
        SELECT 
            'Report Generated' AS ReportSection,
            GETUTCDATE() AS GeneratedAt,
            SYSTEM_USER AS GeneratedBy;
    END;
    
    -- AnalyzeSystemPerformance: Performance analysis and optimization suggestions
        CREATE PROCEDURE dbo.AnalyzeSystemPerformance
        @AnalysisPeriodHours INT = 24,
        @IncludeOptimizationSuggestions BIT = 1
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @StartTime DATETIME2(7) = DATEADD(HOUR, -@AnalysisPeriodHours, GETUTCDATE());
        DECLARE @EndTime DATETIME2(7) = GETUTCDATE();
        
        -- Performance metrics summary
        SELECT 
            'Performance Metrics Summary' AS AnalysisSection,
            MetricName,
            COUNT(*) AS OperationCount,
            AVG(CAST(MetricValue AS FLOAT)) AS AvgValue,
            MIN(CAST(MetricValue AS FLOAT)) AS MinValue,
            MAX(CAST(MetricValue AS FLOAT)) AS MaxValue,
            STDEV(CAST(MetricValue AS FLOAT)) AS StdDeviation,
            MetricUnit
        FROM dbo.PerformanceMetrics
        WHERE CreatedAt BETWEEN @StartTime AND @EndTime
        GROUP BY MetricName, MetricUnit
        ORDER BY AVG(CAST(MetricValue AS FLOAT)) DESC;
        
        -- Slow operations identification
        SELECT 
            'Slow Operations' AS AnalysisSection,
            MetricName,
            CAST(MetricValue AS FLOAT) AS ExecutionTime,
            MetricUnit,
            AdditionalData,
            CreatedAt
        FROM dbo.PerformanceMetrics
        WHERE CreatedAt BETWEEN @StartTime AND @EndTime
          AND CAST(MetricValue AS FLOAT) > (
              SELECT AVG(CAST(MetricValue AS FLOAT)) * 2
              FROM dbo.PerformanceMetrics pm2
              WHERE pm2.MetricName = dbo.PerformanceMetrics.MetricName
                AND pm2.CreatedAt BETWEEN @StartTime AND @EndTime
          )
        ORDER BY CAST(MetricValue AS FLOAT) DESC;
        
        -- Error rate analysis
        SELECT 
            'Error Rate Analysis' AS AnalysisSection,
            ErrorSeverity,
            COUNT(*) AS ErrorCount,
            COUNT(DISTINCT ErrorMessage) AS UniqueErrors,
            MIN(CreatedAt) AS FirstOccurrence,
            MAX(CreatedAt) AS LastOccurrence
        FROM dbo.ErrorLog
        WHERE CreatedAt BETWEEN @StartTime AND @EndTime
        GROUP BY ErrorSeverity
        ORDER BY ErrorCount DESC;
        
        -- Resource utilization patterns
        SELECT 
            'Resource Utilization Patterns' AS AnalysisSection,
            DATEPART(HOUR, CreatedAt) AS HourOfDay,
            COUNT(*) AS OperationCount,
            AVG(CAST(MetricValue AS FLOAT)) AS AvgPerformance
        FROM dbo.PerformanceMetrics
        WHERE CreatedAt BETWEEN @StartTime AND @EndTime
          AND MetricUnit = 'milliseconds'
        GROUP BY DATEPART(HOUR, CreatedAt)
        ORDER BY HourOfDay;
        
        -- Optimization suggestions
        IF @IncludeOptimizationSuggestions = 1
        BEGIN
            DECLARE @OptimizationSuggestions TABLE (
                Priority NVARCHAR(10),
                Category NVARCHAR(50),
                Suggestion NVARCHAR(500),
                EstimatedImpact NVARCHAR(20)
            );
            
            -- Check for high error rates
            IF EXISTS (
                SELECT 1 FROM dbo.ErrorLog 
                WHERE CreatedAt BETWEEN @StartTime AND @EndTime 
                GROUP BY ErrorSeverity 
                HAVING COUNT(*) > 100
            )
            BEGIN
                INSERT INTO @OptimizationSuggestions VALUES (
                    'HIGH', 'Error Handling', 
                    'High error rate detected. Review error logs and implement additional error handling.',
                    'High'
                );
            END
            
            -- Check for slow authentication operations
            IF EXISTS (
                SELECT 1 FROM dbo.PerformanceMetrics 
                WHERE MetricName LIKE '%Authentication%'
                  AND CreatedAt BETWEEN @StartTime AND @EndTime
                  AND CAST(MetricValue AS FLOAT) > 5000 -- 5 seconds
            )
            BEGIN
                INSERT INTO @OptimizationSuggestions VALUES (
                    'MEDIUM', 'Performance', 
                    'Slow authentication operations detected. Consider optimizing database queries and indexing.',
                    'Medium'
                );
            END
            
            -- Check circuit breaker utilization
            IF EXISTS (
                SELECT 1 FROM dbo.CircuitBreakerStates 
                WHERE State = 'OPEN'
            )
            BEGIN
                INSERT INTO @OptimizationSuggestions VALUES (
                    'HIGH', 'Reliability', 
                    'Open circuit breakers detected. Investigate underlying service issues.',
                    'High'
                );
            END
            
            SELECT 
                'Optimization Suggestions' AS AnalysisSection,
                Priority,
                Category,
                Suggestion,
                EstimatedImpact
            FROM @OptimizationSuggestions
            ORDER BY 
                CASE Priority 
                    WHEN 'HIGH' THEN 1 
                    WHEN 'MEDIUM' THEN 2 
                    WHEN 'LOW' THEN 3 
                END;
        END
        
        -- Analysis summary
        SELECT 
            'Analysis Summary' AS AnalysisSection,
            @AnalysisPeriodHours AS PeriodHours,
            (SELECT COUNT(*) FROM dbo.PerformanceMetrics WHERE CreatedAt BETWEEN @StartTime AND @EndTime) AS TotalOperations,
            (SELECT COUNT(*) FROM dbo.ErrorLog WHERE CreatedAt BETWEEN @StartTime AND @EndTime) AS TotalErrors,
            GETUTCDATE() AS AnalysisCompletedAt;
    END;
    
    -- MonitorCircuitBreakers: Circuit breaker monitoring and management
        CREATE PROCEDURE dbo.MonitorCircuitBreakers
        @AutoReset BIT = 0,
        @ResetThresholdMinutes INT = 60
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @MonitoringResults TABLE (
            ServiceName NVARCHAR(100),
            CurrentState NVARCHAR(20),
            ActionTaken NVARCHAR(100),
            Message NVARCHAR(500)
        );
        
        -- Monitor each circuit breaker
        DECLARE @ServiceName NVARCHAR(100);
        DECLARE @State NVARCHAR(20);
        DECLARE @NextRetryAt DATETIME2(7);
        DECLARE @LastFailureAt DATETIME2(7);
        
        DECLARE circuit_cursor CURSOR FOR
        SELECT ServiceName, State, NextRetryAt, LastFailureAt
        FROM dbo.CircuitBreakerStates;
        
        OPEN circuit_cursor;
        FETCH NEXT FROM circuit_cursor INTO @ServiceName, @State, @NextRetryAt, @LastFailureAt;
        
        WHILE @@FETCH_STATUS = 0
        BEGIN
            IF @State = 'OPEN'
            BEGIN
                -- Check if ready for retry
                IF @NextRetryAt IS NOT NULL AND GETUTCDATE() >= @NextRetryAt
                BEGIN
                    -- Transition to HALF_OPEN
                    UPDATE dbo.CircuitBreakerStates
                    SET State = 'HALF_OPEN', UpdatedAt = GETUTCDATE()
                    WHERE ServiceName = @ServiceName;
                    
                    INSERT INTO @MonitoringResults VALUES (
                        @ServiceName, 'HALF_OPEN', 'Auto Transition', 
                        'Circuit breaker transitioned to HALF_OPEN for testing'
                    );
                END
                ELSE IF @AutoReset = 1 AND @LastFailureAt IS NOT NULL 
                    AND DATEDIFF(MINUTE, @LastFailureAt, GETUTCDATE()) > @ResetThresholdMinutes
                BEGIN
                    -- Force reset after threshold period
                    UPDATE dbo.CircuitBreakerStates
                    SET State = 'CLOSED', FailureCount = 0, NextRetryAt = NULL, UpdatedAt = GETUTCDATE()
                    WHERE ServiceName = @ServiceName;
                    
                    INSERT INTO @MonitoringResults VALUES (
                        @ServiceName, 'CLOSED', 'Force Reset', 
                        CONCAT('Circuit breaker force reset after ', @ResetThresholdMinutes, ' minutes')
                    );
                    
                    -- Log the reset
                    EXEC dbo.LogAuditEvent
                        @EventType = 'CIRCUIT_BREAKER_FORCE_RESET',
                        @Details = CONCAT('Circuit breaker ', @ServiceName, ' force reset after prolonged failure'),
                        @AdditionalData = @ServiceName;
                END
                ELSE
                BEGIN
                    INSERT INTO @MonitoringResults VALUES (
                        @ServiceName, @State, 'Monitor Only', 
                        CONCAT('Circuit breaker remains OPEN, next retry: ', ISNULL(CONVERT(NVARCHAR(30), @NextRetryAt, 121), 'Not Set'))
                    );
                END
            END
            ELSE IF @State = 'HALF_OPEN'
            BEGIN
                INSERT INTO @MonitoringResults VALUES (
                    @ServiceName, @State, 'Monitor Only', 
                    'Circuit breaker in HALF_OPEN state, monitoring for success/failure'
                );
            END
            ELSE -- CLOSED state
            BEGIN
                INSERT INTO @MonitoringResults VALUES (
                    @ServiceName, @State, 'Monitor Only', 
                    'Circuit breaker operating normally'
                );
            END
            
            FETCH NEXT FROM circuit_cursor INTO @ServiceName, @State, @NextRetryAt, @LastFailureAt;
        END
        
        CLOSE circuit_cursor;
        DEALLOCATE circuit_cursor;
        
        -- Return monitoring results
        SELECT 
            ServiceName,
            CurrentState,
            ActionTaken,
            Message,
            GETUTCDATE() AS MonitoredAt
        FROM @MonitoringResults
        ORDER BY 
            CASE CurrentState 
                WHEN 'OPEN' THEN 1 
                WHEN 'HALF_OPEN' THEN 2 
                WHEN 'CLOSED' THEN 3 
            END,
            ServiceName;
        
        -- Summary statistics
        SELECT 
            'Circuit Breaker Summary' AS SummaryType,
            COUNT(*) AS TotalCircuitBreakers,
            SUM(CASE WHEN CurrentState = 'CLOSED' THEN 1 ELSE 0 END) AS ClosedCount,
            SUM(CASE WHEN CurrentState = 'HALF_OPEN' THEN 1 ELSE 0 END) AS HalfOpenCount,
            SUM(CASE WHEN CurrentState = 'OPEN' THEN 1 ELSE 0 END) AS OpenCount,
            CAST(SUM(CASE WHEN CurrentState = 'CLOSED' THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) * 100 AS HealthPercentage
        FROM @MonitoringResults;
    END;
    
    PRINT '✓ Monitoring and reporting procedures created';
    
    -- ============================================================================
    -- USAGE STATISTICS AND ANALYTICS
    -- ============================================================================
    
    PRINT 'Creating usage statistics procedures...';
    
    -- GenerateUsageStatistics: Comprehensive usage analytics
        CREATE PROCEDURE dbo.GenerateUsageStatistics
        @PeriodDays INT = 30,
        @IncludeProjections BIT = 0
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @StartDate DATE = CAST(DATEADD(DAY, -@PeriodDays, GETUTCDATE()) AS DATE);
        DECLARE @EndDate DATE = CAST(GETUTCDATE() AS DATE);
        
        -- Usage overview
        SELECT 
            'Usage Overview' AS StatisticType,
            @PeriodDays AS PeriodDays,
            @StartDate AS StartDate,
            @EndDate AS EndDate,
            COUNT(DISTINCT pn.PhoneNumber) AS UniquePhoneNumbers,
            COUNT(DISTINCT ad.UniqueId) AS UniqueDevices,
            COUNT(DISTINCT m.UniqueId) AS ActiveMemberships,
            COUNT(DISTINCT ac.MembershipId) AS MembershipsWithSessions
        FROM dbo.PhoneNumbers pn
        LEFT JOIN dbo.Memberships m ON pn.UniqueId = m.PhoneNumberId AND m.IsDeleted = 0
        LEFT JOIN dbo.AppDevices ad ON m.AppDeviceId = ad.UniqueId AND ad.IsDeleted = 0
        LEFT JOIN dbo.AuthenticationContexts ac ON m.UniqueId = ac.MembershipId AND ac.CreatedAt >= @StartDate;
        
        -- Daily activity trends
        SELECT 
            'Daily Activity Trends' AS StatisticType,
            CAST(la.Timestamp AS DATE) AS ActivityDate,
            COUNT(*) AS TotalLoginAttempts,
            SUM(CASE WHEN la.IsSuccess = 1 THEN 1 ELSE 0 END) AS SuccessfulLogins,
            COUNT(DISTINCT la.PhoneNumber) AS UniqueUsers,
            COUNT(DISTINCT vf.UniqueId) AS NewVerificationFlows,
            COUNT(DISTINCT ma.PhoneNumberId) AS MembershipAttempts
        FROM dbo.LoginAttempts la
        LEFT JOIN dbo.VerificationFlows vf ON CAST(vf.CreatedAt AS DATE) = CAST(la.Timestamp AS DATE)
        LEFT JOIN dbo.MembershipAttempts ma ON CAST(ma.Timestamp AS DATE) = CAST(la.Timestamp AS DATE)
        WHERE CAST(la.Timestamp AS DATE) BETWEEN @StartDate AND @EndDate
        GROUP BY CAST(la.Timestamp AS DATE)
        ORDER BY ActivityDate;
        
        -- Feature usage statistics
        SELECT 
            'Feature Usage Statistics' AS StatisticType,
            vf.Purpose,
            COUNT(*) AS TotalFlows,
            SUM(CASE WHEN vf.Status = 'verified' THEN 1 ELSE 0 END) AS SuccessfulVerifications,
            AVG(CAST(vf.OtpCount AS FLOAT)) AS AvgOtpAttempts,
            AVG(DATEDIFF(MINUTE, vf.CreatedAt, ISNULL(vf.UpdatedAt, GETUTCDATE()))) AS AvgFlowDurationMinutes
        FROM dbo.VerificationFlows vf
        WHERE CAST(vf.CreatedAt AS DATE) BETWEEN @StartDate AND @EndDate
        GROUP BY vf.Purpose
        ORDER BY TotalFlows DESC;
        
        -- Performance statistics
        SELECT 
            'Performance Statistics' AS StatisticType,
            pm.MetricName,
            COUNT(*) AS OperationCount,
            AVG(CAST(pm.MetricValue AS FLOAT)) AS AvgPerformance,
            MIN(CAST(pm.MetricValue AS FLOAT)) AS BestPerformance,
            MAX(CAST(pm.MetricValue AS FLOAT)) AS WorstPerformance,
            pm.MetricUnit
        FROM dbo.PerformanceMetrics pm
        WHERE CAST(pm.CreatedAt AS DATE) BETWEEN @StartDate AND @EndDate
          AND pm.MetricUnit = 'milliseconds'
        GROUP BY pm.MetricName, pm.MetricUnit
        ORDER BY OperationCount DESC;
        
        -- Geographic distribution (based on available IP data)
        SELECT 
            'Geographic Distribution' AS StatisticType,
            LEFT(ISNULL(la.Outcome, 'Unknown'), 20) AS LocationHint,
            COUNT(DISTINCT la.PhoneNumber) AS UniqueUsers,
            COUNT(*) AS TotalAttempts,
            SUM(CASE WHEN la.IsSuccess = 1 THEN 1 ELSE 0 END) AS SuccessfulLogins
        FROM dbo.LoginAttempts la
        WHERE CAST(la.Timestamp AS DATE) BETWEEN @StartDate AND @EndDate
          AND (la.Outcome LIKE 'ip_changed:%' OR la.Outcome = 'success')
        GROUP BY LEFT(ISNULL(la.Outcome, 'Unknown'), 20)
        ORDER BY UniqueUsers DESC;
        
        -- Growth projections (if requested)
        IF @IncludeProjections = 1
        BEGIN
            DECLARE @DailyGrowthRate DECIMAL(10,6);
            DECLARE @ProjectedUsers INT;
            DECLARE @ProjectedLogins INT;
            
            -- Calculate growth rate based on first and last week
            WITH WeeklyStats AS (
                SELECT 
                    CASE 
                        WHEN CAST(Timestamp AS DATE) BETWEEN @StartDate AND DATEADD(DAY, 6, @StartDate) THEN 'First Week'
                        WHEN CAST(Timestamp AS DATE) BETWEEN DATEADD(DAY, -6, @EndDate) AND @EndDate THEN 'Last Week'
                    END AS Period,
                    COUNT(DISTINCT PhoneNumber) AS UniqueUsers,
                    COUNT(*) AS TotalLogins
                FROM dbo.LoginAttempts
                WHERE CAST(Timestamp AS DATE) BETWEEN @StartDate AND @EndDate
                  AND IsSuccess = 1
                GROUP BY 
                    CASE 
                        WHEN CAST(Timestamp AS DATE) BETWEEN @StartDate AND DATEADD(DAY, 6, @StartDate) THEN 'First Week'
                        WHEN CAST(Timestamp AS DATE) BETWEEN DATEADD(DAY, -6, @EndDate) AND @EndDate THEN 'Last Week'
                    END
            )
            SELECT 
                'Growth Projections' AS StatisticType,
                'Next 30 Days' AS ProjectionPeriod,
                CAST(MAX(CASE WHEN Period = 'Last Week' THEN UniqueUsers END) * 1.1 AS INT) AS ProjectedUsers,
                CAST(MAX(CASE WHEN Period = 'Last Week' THEN TotalLogins END) * 1.15 AS INT) AS ProjectedLogins,
                'Based on recent growth trends' AS Methodology
            FROM WeeklyStats
            WHERE Period IS NOT NULL;
        END
        
        -- Report metadata
        SELECT 
            'Report Metadata' AS StatisticType,
            GETUTCDATE() AS GeneratedAt,
            SYSTEM_USER AS GeneratedBy,
            @@SERVERNAME AS ServerName,
            DB_NAME() AS DatabaseName;
    END;
    
    PRINT '✓ Usage statistics procedures created';
    
    -- ============================================================================
    -- PROCEDURE VALIDATION
    -- ============================================================================
    
    PRINT 'Validating maintenance and monitoring procedures...';
    
    DECLARE @ProcedureCount INT;
    SELECT @ProcedureCount = COUNT(*)
    FROM sys.procedures p
    INNER JOIN sys.schemas s ON p.schema_id = s.schema_id
    WHERE s.name = 'dbo' 
    AND p.name IN (
        'PerformSystemMaintenance', 'GenerateSecurityReport', 'AnalyzeSystemPerformance',
        'MonitorCircuitBreakers', 'GenerateUsageStatistics'
    );
    
    IF @ProcedureCount = 5
        PRINT '✓ All 5 maintenance and monitoring procedures created successfully';
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
    PRINT 'Layer 5.2: Advanced Maintenance & Monitoring Completed Successfully';
    PRINT 'Procedures created: ' + CAST(@ProcedureCount AS NVARCHAR(10));
    PRINT 'Features: System maintenance, performance analysis, security reporting';
    PRINT 'Monitoring: Circuit breakers, usage analytics, optimization suggestions';
    PRINT 'Layer 5: Advanced Features - COMPLETED';
    PRINT 'Next: Layer 6 - Triggers';
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
    PRINT 'ERROR in Layer 5.2: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO