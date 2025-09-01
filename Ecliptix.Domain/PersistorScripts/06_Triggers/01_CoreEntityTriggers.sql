/*
================================================================================
Layer 6.1: Core Entity Triggers
================================================================================
Purpose: Automatic UpdatedAt timestamp management for core domain entities

Dependencies: 
- Layer 1: Configuration & Core Infrastructure (01_SystemConfiguration.sql, 02_LoggingInfrastructure.sql)
- Layer 2: Core Domain Tables (01_CoreDomainTables.sql)

Version: 1.0.0
Author: Ecliptix Development Team
Created: 2024-08-24

Features:
- Automatic timestamp management for core entities
- Recursion prevention for UpdatedAt field updates
- Performance optimized with SET NOCOUNT ON
- Transaction safe operations

Tables Covered:
- AppDevices (mobile device registration)
- PhoneNumbers (phone number registry)
- PhoneNumberDevices (device-phone associations)
================================================================================
*/

-- Log deployment start
INSERT INTO dbo.DeploymentLog (ScriptName, Status, StartTime, Message)
VALUES ('06_Triggers/01_CoreEntityTriggers.sql', 'RUNNING', GETUTCDATE(), 'Starting Core Entity Triggers deployment');

DECLARE @DeploymentId BIGINT = SCOPE_IDENTITY();
DECLARE @ErrorMessage NVARCHAR(4000);
DECLARE @StartTime DATETIME2(7) = GETUTCDATE();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- Performance tracking
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'TRIGGER_DEPLOYMENT',
        @TableName = 'CoreEntityTriggers',
        @Duration = 0,
        @RowsAffected = 0,
        @AdditionalInfo = 'Starting Core Entity Triggers deployment';

    PRINT '🚀 Deploying Core Entity Triggers...';

    -- Drop existing triggers if they exist
    IF OBJECT_ID('dbo.TRG_AppDevices_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_AppDevices_Update;
    
    IF OBJECT_ID('dbo.TRG_PhoneNumbers_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_PhoneNumbers_Update;
        
    IF OBJECT_ID('dbo.TRG_PhoneNumberDevices_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_PhoneNumberDevices_Update;

    /*
    ================================================================================
    Trigger: TRG_AppDevices_Update
    Purpose: Automatic UpdatedAt timestamp management for AppDevices table
    ================================================================================
    */
    PRINT '📱 Creating AppDevices update trigger...';
    
        CREATE TRIGGER TRG_AppDevices_Update ON dbo.AppDevices FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.AppDevices t
        INNER JOIN inserted i ON t.Id = i.Id;
    END;

    /*
    ================================================================================
    Trigger: TRG_PhoneNumbers_Update
    Purpose: Automatic UpdatedAt timestamp management for PhoneNumbers table
    ================================================================================
    */
    PRINT '📞 Creating PhoneNumbers update trigger...';
    
        CREATE TRIGGER TRG_PhoneNumbers_Update ON dbo.PhoneNumbers FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.PhoneNumbers t
        INNER JOIN inserted i ON t.Id = i.Id;
    END;

    /*
    ================================================================================
    Trigger: TRG_PhoneNumberDevices_Update
    Purpose: Automatic UpdatedAt timestamp management for PhoneNumberDevices table
    ================================================================================
    */
    PRINT '🔗 Creating PhoneNumberDevices update trigger...';
    
        CREATE TRIGGER TRG_PhoneNumberDevices_Update ON dbo.PhoneNumberDevices FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows (composite key handling)
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.PhoneNumberDevices t
        INNER JOIN inserted i ON t.PhoneNumberId = i.PhoneNumberId AND t.AppDeviceId = i.AppDeviceId;
    END;

    -- Performance tracking
    DECLARE @Duration INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'TRIGGER_DEPLOYMENT',
        @TableName = 'CoreEntityTriggers',
        @Duration = @Duration,
        @RowsAffected = 3,
        @AdditionalInfo = 'Core Entity Triggers deployed successfully';

    COMMIT TRANSACTION;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'SUCCESS', 
        EndTime = GETUTCDATE(), 
        Message = 'Core Entity Triggers deployed successfully - 3 triggers created',
        RowsAffected = 3
    WHERE Id = @DeploymentId;

    PRINT '✅ Core Entity Triggers deployment completed successfully';
    PRINT CONCAT('📊 Deployment completed in ', @Duration, 'ms');
    
END TRY
BEGIN CATCH
    -- Rollback transaction on error
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    
    SET @ErrorMessage = ERROR_MESSAGE();
    
    -- Log error
    EXEC dbo.LogError
        @ProcedureName = '06_Triggers/01_CoreEntityTriggers.sql',
        @ErrorMessage = @ErrorMessage;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'ERROR', 
        EndTime = GETUTCDATE(), 
        Message = CONCAT('Core Entity Triggers deployment failed: ', @ErrorMessage)
    WHERE Id = @DeploymentId;
    
    PRINT '❌ Core Entity Triggers deployment failed';
    PRINT CONCAT('Error: ', @ErrorMessage);
    
    -- Re-raise error to halt deployment
    THROW;
END CATCH;