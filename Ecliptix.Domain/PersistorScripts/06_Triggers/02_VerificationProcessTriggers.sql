/*
================================================================================
Layer 6.2: Verification Process Triggers
================================================================================
Purpose: Automatic UpdatedAt timestamp management and audit logging for 
         verification process entities

Dependencies: 
- Layer 1: Configuration & Core Infrastructure (01_SystemConfiguration.sql, 02_LoggingInfrastructure.sql)
- Layer 2: Core Domain Tables (01_CoreDomainTables.sql)

Version: 1.0.0
Author: Ecliptix Development Team
Created: 2024-08-24

Features:
- Automatic timestamp management for verification entities
- Enhanced audit logging for OTP status changes
- Configuration-driven audit behavior
- Performance optimized with bulk operation handling
- Comprehensive error handling and logging

Tables Covered:
- VerificationFlows (verification process tracking)
- OtpRecords (OTP management with enhanced audit logging)
- FailedOtpAttempts (OTP failure tracking)
================================================================================
*/

-- Log deployment start
INSERT INTO dbo.DeploymentLog (ScriptName, Status, StartTime, Message)
VALUES ('06_Triggers/02_VerificationProcessTriggers.sql', 'RUNNING', GETUTCDATE(), 'Starting Verification Process Triggers deployment');

DECLARE @DeploymentId BIGINT = SCOPE_IDENTITY();
DECLARE @ErrorMessage NVARCHAR(4000);
DECLARE @StartTime DATETIME2(7) = GETUTCDATE();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- Performance tracking
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'TRIGGER_DEPLOYMENT',
        @TableName = 'VerificationProcessTriggers',
        @Duration = 0,
        @RowsAffected = 0,
        @AdditionalInfo = 'Starting Verification Process Triggers deployment';

    PRINT '🚀 Deploying Verification Process Triggers...';

    -- Drop existing triggers if they exist
    IF OBJECT_ID('dbo.TRG_VerificationFlows_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_VerificationFlows_Update;
    
    IF OBJECT_ID('dbo.TRG_OtpRecords_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_OtpRecords_Update;
        
    IF OBJECT_ID('dbo.TRG_FailedOtpAttempts_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_FailedOtpAttempts_Update;

    /*
    ================================================================================
    Trigger: TRG_VerificationFlows_Update
    Purpose: Automatic UpdatedAt timestamp management for VerificationFlows table
    ================================================================================
    */
    PRINT '🔄 Creating VerificationFlows update trigger...';
    
    EXEC('
    CREATE TRIGGER TRG_VerificationFlows_Update ON dbo.VerificationFlows FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.VerificationFlows t
        INNER JOIN inserted i ON t.Id = i.Id;
    END;
    ');

    /*
    ================================================================================
    Trigger: TRG_OtpRecords_Update (Enhanced)
    Purpose: Automatic UpdatedAt timestamp management with comprehensive audit logging
    
    Features:
    - Automatic timestamp updates
    - Configurable audit logging for status changes
    - Performance optimized for bulk operations
    - Comprehensive error handling
    - Status and activation state change tracking
    ================================================================================
    */
    PRINT '🔐 Creating enhanced OtpRecords update trigger...';
    
    EXEC('
    CREATE TRIGGER TRG_OtpRecords_Update ON dbo.OtpRecords FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Skip if no rows affected or avoiding recursion
        IF @@ROWCOUNT = 0 OR UPDATE(UpdatedAt) RETURN;
        
        BEGIN TRY
            -- Update timestamp for all affected rows
            UPDATE t SET UpdatedAt = GETUTCDATE()
            FROM dbo.OtpRecords t
            INNER JOIN inserted i ON t.Id = i.Id;
            
            -- Log audit events for significant status changes (if enabled and not bulk operations)
            -- Only process audit logging if explicitly enabled and row count is reasonable
            IF dbo.GetConfigValue(''Audit.LogOtpChanges'') = ''1'' AND @@ROWCOUNT <= 100
            BEGIN
                DECLARE audit_cursor CURSOR LOCAL FAST_FORWARD FOR
                SELECT 
                    i.UniqueId,
                    d.Status AS OldStatus,
                    i.Status AS NewStatus,
                    d.IsActive AS OldIsActive,
                    i.IsActive AS NewIsActive
                FROM inserted i
                INNER JOIN deleted d ON i.Id = d.Id
                WHERE i.Status != d.Status OR i.IsActive != d.IsActive;
                
                DECLARE @OtpUniqueId UNIQUEIDENTIFIER, @OldStatus NVARCHAR(20), @NewStatus NVARCHAR(20);
                DECLARE @OldIsActive BIT, @NewIsActive BIT;
                
                OPEN audit_cursor;
                FETCH NEXT FROM audit_cursor INTO @OtpUniqueId, @OldStatus, @NewStatus, @OldIsActive, @NewIsActive;
                
                WHILE @@FETCH_STATUS = 0
                BEGIN
                    -- Log status change
                    IF @OldStatus != @NewStatus
                    BEGIN
                        EXEC dbo.LogAuditEvent
                            @TableName = ''OtpRecords'',
                            @OperationType = ''STATUS_CHANGE'',
                            @RecordId = @OtpUniqueId,
                            @OldValues = CONCAT(''Status:'', @OldStatus),
                            @NewValues = CONCAT(''Status:'', @NewStatus),
                            @ApplicationContext = ''TRG_OtpRecords_Update'',
                            @Success = 1;
                    END
                    
                    -- Log activation state change
                    IF @OldIsActive != @NewIsActive
                    BEGIN
                        EXEC dbo.LogAuditEvent
                            @TableName = ''OtpRecords'',
                            @OperationType = ''ACTIVATION_CHANGE'',
                            @RecordId = @OtpUniqueId,
                            @OldValues = CONCAT(''IsActive:'', CAST(@OldIsActive AS NVARCHAR(1))),
                            @NewValues = CONCAT(''IsActive:'', CAST(@NewIsActive AS NVARCHAR(1))),
                            @ApplicationContext = ''TRG_OtpRecords_Update'',
                            @Success = 1;
                    END
                    
                    FETCH NEXT FROM audit_cursor INTO @OtpUniqueId, @OldStatus, @NewStatus, @OldIsActive, @NewIsActive;
                END
                
                CLOSE audit_cursor;
                DEALLOCATE audit_cursor;
            END
            
        END TRY
        BEGIN CATCH
            -- Log trigger error but do not fail the transaction
            -- This ensures data updates succeed even if audit logging fails
            EXEC dbo.LogError
                @ProcedureName = ''TRG_OtpRecords_Update'',
                @ErrorMessage = ERROR_MESSAGE();
        END CATCH
    END;
    ');

    /*
    ================================================================================
    Trigger: TRG_FailedOtpAttempts_Update
    Purpose: Automatic UpdatedAt timestamp management for FailedOtpAttempts table
    ================================================================================
    */
    PRINT '❌ Creating FailedOtpAttempts update trigger...';
    
    EXEC('
    CREATE TRIGGER TRG_FailedOtpAttempts_Update ON dbo.FailedOtpAttempts FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.FailedOtpAttempts t
        INNER JOIN inserted i ON t.Id = i.Id;
    END;
    ');

    -- Ensure audit configuration exists
    PRINT '⚙️ Configuring audit settings...';
    
    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Audit.LogOtpChanges')
    BEGIN
        EXEC dbo.SetConfigValue
            @ConfigKey = 'Audit.LogOtpChanges',
            @ConfigValue = '1',
            @DataType = 'bool',
            @Description = 'Enable detailed OTP change logging in triggers',
            @Category = 'Security';
        
        PRINT '   ✓ OTP audit logging configuration created';
    END

    -- Performance tracking
    DECLARE @Duration INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'TRIGGER_DEPLOYMENT',
        @TableName = 'VerificationProcessTriggers',
        @Duration = @Duration,
        @RowsAffected = 3,
        @AdditionalInfo = 'Verification Process Triggers deployed successfully with audit capabilities';

    COMMIT TRANSACTION;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'SUCCESS', 
        EndTime = GETUTCDATE(), 
        Message = 'Verification Process Triggers deployed successfully - 3 triggers created with audit capabilities',
        RowsAffected = 3
    WHERE Id = @DeploymentId;

    PRINT '✅ Verification Process Triggers deployment completed successfully';
    PRINT CONCAT('📊 Deployment completed in ', @Duration, 'ms');
    PRINT '   ✓ Standard timestamp triggers created';
    PRINT '   ✓ Enhanced OTP audit logging enabled';
    PRINT '   ✓ Configuration-driven audit behavior configured';
    
END TRY
BEGIN CATCH
    -- Rollback transaction on error
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    
    SET @ErrorMessage = ERROR_MESSAGE();
    
    -- Log error
    EXEC dbo.LogError
        @ProcedureName = '06_Triggers/02_VerificationProcessTriggers.sql',
        @ErrorMessage = @ErrorMessage;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'ERROR', 
        EndTime = GETUTCDATE(), 
        Message = CONCAT('Verification Process Triggers deployment failed: ', @ErrorMessage)
    WHERE Id = @DeploymentId;
    
    PRINT '❌ Verification Process Triggers deployment failed';
    PRINT CONCAT('Error: ', @ErrorMessage);
    
    -- Re-raise error to halt deployment
    THROW;
END CATCH;