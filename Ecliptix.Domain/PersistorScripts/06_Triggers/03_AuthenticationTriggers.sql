/*
================================================================================
Layer 6.3: Authentication & Membership Triggers
================================================================================
Purpose: Automatic UpdatedAt timestamp management for authentication and 
         membership entities

Dependencies: 
- Layer 1: Configuration & Core Infrastructure (01_SystemConfiguration.sql, 02_LoggingInfrastructure.sql)
- Layer 2: Core Domain Tables (01_CoreDomainTables.sql)

Version: 1.0.0
Author: Ecliptix Development Team
Created: 2024-08-24

Features:
- Automatic timestamp management for authentication entities
- Composite key handling for complex table relationships
- Recursion prevention for UpdatedAt field updates
- Performance optimized with SET NOCOUNT ON
- Transaction safe operations

Tables Covered:
- Memberships (user membership records)
- MembershipAttempts (membership creation attempts)
- AuthenticationContexts (authentication session contexts)
- AuthenticationStates (authentication rate limiting states)
- LoginAttempts (login attempt tracking)
================================================================================
*/

-- Log deployment start
INSERT INTO dbo.DeploymentLog (ScriptName, Status, StartTime, Message)
VALUES ('06_Triggers/03_AuthenticationTriggers.sql', 'RUNNING', GETUTCDATE(), 'Starting Authentication & Membership Triggers deployment');

DECLARE @DeploymentId BIGINT = SCOPE_IDENTITY();
DECLARE @ErrorMessage NVARCHAR(4000);
DECLARE @StartTime DATETIME2(7) = GETUTCDATE();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- Performance tracking
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'TRIGGER_DEPLOYMENT',
        @TableName = 'AuthenticationTriggers',
        @Duration = 0,
        @RowsAffected = 0,
        @AdditionalInfo = 'Starting Authentication & Membership Triggers deployment';

    PRINT '🚀 Deploying Authentication & Membership Triggers...';

    -- Drop existing triggers if they exist
    IF OBJECT_ID('dbo.TRG_Memberships_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_Memberships_Update;
    
    IF OBJECT_ID('dbo.TRG_MembershipAttempts_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_MembershipAttempts_Update;
        
    IF OBJECT_ID('dbo.TRG_AuthenticationContexts_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_AuthenticationContexts_Update;
        
    IF OBJECT_ID('dbo.TRG_AuthenticationStates_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_AuthenticationStates_Update;
        
    IF OBJECT_ID('dbo.TRG_LoginAttempts_Update', 'TR') IS NOT NULL 
        DROP TRIGGER dbo.TRG_LoginAttempts_Update;

    /*
    ================================================================================
    Trigger: TRG_Memberships_Update
    Purpose: Automatic UpdatedAt timestamp management for Memberships table
    ================================================================================
    */
    PRINT '👤 Creating Memberships update trigger...';
    
        CREATE TRIGGER TRG_Memberships_Update ON dbo.Memberships FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.Memberships t
        INNER JOIN inserted i ON t.Id = i.Id;
    END;

    /*
    ================================================================================
    Trigger: TRG_MembershipAttempts_Update
    Purpose: Automatic UpdatedAt timestamp management for MembershipAttempts table
    ================================================================================
    */
    PRINT '📝 Creating MembershipAttempts update trigger...';
    
        CREATE TRIGGER TRG_MembershipAttempts_Update ON dbo.MembershipAttempts FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.MembershipAttempts t
        INNER JOIN inserted i ON t.Id = i.Id;
    END;

    /*
    ================================================================================
    Trigger: TRG_AuthenticationContexts_Update
    Purpose: Automatic UpdatedAt timestamp management for AuthenticationContexts table
    
    Note: This table manages authentication session contexts with complex state management
    ================================================================================
    */
    PRINT '🔐 Creating AuthenticationContexts update trigger...';
    
        CREATE TRIGGER TRG_AuthenticationContexts_Update ON dbo.AuthenticationContexts FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.AuthenticationContexts t
        INNER JOIN inserted i ON t.Id = i.Id;
    END;

    /*
    ================================================================================
    Trigger: TRG_AuthenticationStates_Update
    Purpose: Automatic UpdatedAt timestamp management for AuthenticationStates table
    
    Note: This table uses MobileNumberId as primary key (UNIQUEIDENTIFIER)
    ================================================================================
    */
    PRINT '⏱️ Creating AuthenticationStates update trigger...';
    
        CREATE TRIGGER TRG_AuthenticationStates_Update ON dbo.AuthenticationStates FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows (primary key is MobileNumberId)
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.AuthenticationStates t
        INNER JOIN inserted i ON t.MobileNumberId = i.MobileNumberId;
    END;

    /*
    ================================================================================
    Trigger: TRG_LoginAttempts_Update
    Purpose: Automatic UpdatedAt timestamp management for LoginAttempts table
    ================================================================================
    */
    PRINT '🚪 Creating LoginAttempts update trigger...';
    
        CREATE TRIGGER TRG_LoginAttempts_Update ON dbo.LoginAttempts FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Prevent recursion when UpdatedAt field itself is being updated
        IF UPDATE(UpdatedAt) RETURN;
        
        -- Update timestamp for all affected rows
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.LoginAttempts t
        INNER JOIN inserted i ON t.Id = i.Id;
    END;

    -- Ensure membership audit configuration exists
    PRINT '⚙️ Configuring membership audit settings...';
    
    IF NOT EXISTS (SELECT 1 FROM dbo.SystemConfiguration WHERE ConfigKey = 'Audit.LogMembershipChanges')
    BEGIN
        EXEC dbo.SetConfigValue
            @ConfigKey = 'Audit.LogMembershipChanges',
            @ConfigValue = '1',
            @DataType = 'bool',
            @Description = 'Enable detailed membership change logging',
            @Category = 'Security';
        
        PRINT '   ✓ Membership audit logging configuration created';
    END

    -- Performance tracking
    DECLARE @Duration INT = DATEDIFF(MILLISECOND, @StartTime, GETUTCDATE());
    EXEC dbo.LogPerformanceMetric
        @OperationType = 'TRIGGER_DEPLOYMENT',
        @TableName = 'AuthenticationTriggers',
        @Duration = @Duration,
        @RowsAffected = 5,
        @AdditionalInfo = 'Authentication & Membership Triggers deployed successfully';

    COMMIT TRANSACTION;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'SUCCESS', 
        EndTime = GETUTCDATE(), 
        Message = 'Authentication & Membership Triggers deployed successfully - 5 triggers created',
        RowsAffected = 5
    WHERE Id = @DeploymentId;

    PRINT '✅ Authentication & Membership Triggers deployment completed successfully';
    PRINT CONCAT('📊 Deployment completed in ', @Duration, 'ms');
    PRINT '   ✓ Memberships trigger created';
    PRINT '   ✓ MembershipAttempts trigger created';
    PRINT '   ✓ AuthenticationContexts trigger created';
    PRINT '   ✓ AuthenticationStates trigger created';
    PRINT '   ✓ LoginAttempts trigger created';
    PRINT '   ✓ Membership audit configuration established';
    
END TRY
BEGIN CATCH
    -- Rollback transaction on error
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
    
    SET @ErrorMessage = ERROR_MESSAGE();
    
    -- Log error
    EXEC dbo.LogError
        @ProcedureName = '06_Triggers/03_AuthenticationTriggers.sql',
        @ErrorMessage = @ErrorMessage;
    
    -- Update deployment log
    UPDATE dbo.DeploymentLog 
    SET Status = 'ERROR', 
        EndTime = GETUTCDATE(), 
        Message = CONCAT('Authentication & Membership Triggers deployment failed: ', @ErrorMessage)
    WHERE Id = @DeploymentId;
    
    PRINT '❌ Authentication & Membership Triggers deployment failed';
    PRINT CONCAT('Error: ', @ErrorMessage);
    
    -- Re-raise error to halt deployment
    THROW;
END CATCH;