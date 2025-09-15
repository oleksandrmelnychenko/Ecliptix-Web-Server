/*
================================================================================
Database Data Cleanup Script
================================================================================
Purpose: Remove all data from the Ecliptix database while preserving table structures
Author: Claude Code Assistant
Created: 2025-09-13
Database: memberships (SQL Server)

IMPORTANT NOTES:
- This script removes ALL DATA from the database
- Table structures, indexes, and constraints are preserved
- Identity columns are reset to start from 1
- Use with extreme caution in production environments
- Always backup your database before running this script

Usage:
1. Connect to your SQL Server instance
2. Ensure you're in the correct database context
3. Review the script thoroughly before execution
4. Execute the entire script as a single batch
================================================================================
*/

-- Use target database
USE [memberships]; -- Replace with your actual database name if different
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Database Data Cleanup Script';
PRINT 'Started at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
PRINT '⚠️  WARNING: This will remove ALL DATA from the database!';
PRINT '================================================================================';
PRINT '';

-- Confirmation check (comment out for automated execution)
/*
DECLARE @Confirmation NVARCHAR(10);
SET @Confirmation = 'NO'; -- Change to 'YES' to proceed
IF @Confirmation != 'YES'
BEGIN
    PRINT '❌ Confirmation required. Set @Confirmation = ''YES'' to proceed.';
    RETURN;
END
*/

BEGIN TRY
    BEGIN TRANSACTION DataCleanup;

    -- ============================================================================
    -- STEP 1: DISABLE FOREIGN KEY CONSTRAINTS
    -- ============================================================================

    PRINT 'Step 1: Disabling foreign key constraints...';

    -- Disable all foreign key constraints to avoid dependency issues
    EXEC sp_MSforeachtable 'ALTER TABLE ? NOCHECK CONSTRAINT ALL';

    PRINT '✓ All foreign key constraints disabled';
    PRINT '';

    -- ============================================================================
    -- STEP 2: DATA CLEANUP (ORDER MATTERS FOR REFERENTIAL INTEGRITY)
    -- ============================================================================

    PRINT 'Step 2: Cleaning up data from all tables...';

    -- Log the cleanup start
    INSERT INTO dbo.EventLog (EventType, Message)
    VALUES ('SYSTEM', 'Database cleanup initiated at ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121));

    DECLARE @DeletedRows TABLE (
        TableName NVARCHAR(255),
        RowCount INT,
        CleanupTime DATETIME2(7)
    );

    -- Activity Tracking Tables (No dependencies)
    IF EXISTS (SELECT 1 FROM dbo.EventLog WHERE EventType != 'SYSTEM' OR Message NOT LIKE 'Database cleanup%')
    BEGIN
        DELETE FROM dbo.EventLog WHERE EventType != 'SYSTEM' OR Message NOT LIKE 'Database cleanup%';
        INSERT INTO @DeletedRows VALUES ('EventLog', @@ROWCOUNT, GETUTCDATE());
        PRINT '✓ EventLog data cleared (preserving cleanup logs)';
    END
    ELSE
        PRINT '✓ EventLog already empty (preserving cleanup logs)';

    IF EXISTS (SELECT 1 FROM dbo.LoginAttempts)
    BEGIN
        DELETE FROM dbo.LoginAttempts;
        INSERT INTO @DeletedRows VALUES ('LoginAttempts', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.LoginAttempts', RESEED, 0);
        PRINT '✓ LoginAttempts data cleared and identity reset';
    END
    ELSE
        PRINT '✓ LoginAttempts already empty';

    IF EXISTS (SELECT 1 FROM dbo.MembershipAttempts)
    BEGIN
        DELETE FROM dbo.MembershipAttempts;
        INSERT INTO @DeletedRows VALUES ('MembershipAttempts', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.MembershipAttempts', RESEED, 0);
        PRINT '✓ MembershipAttempts data cleared and identity reset';
    END
    ELSE
        PRINT '✓ MembershipAttempts already empty';

    -- Authentication Tables
    IF EXISTS (SELECT 1 FROM dbo.AuthenticationStates)
    BEGIN
        DELETE FROM dbo.AuthenticationStates;
        INSERT INTO @DeletedRows VALUES ('AuthenticationStates', @@ROWCOUNT, GETUTCDATE());
        PRINT '✓ AuthenticationStates data cleared';
    END
    ELSE
        PRINT '✓ AuthenticationStates already empty';

    IF EXISTS (SELECT 1 FROM dbo.AuthenticationContexts)
    BEGIN
        DELETE FROM dbo.AuthenticationContexts;
        INSERT INTO @DeletedRows VALUES ('AuthenticationContexts', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.AuthenticationContexts', RESEED, 0);
        PRINT '✓ AuthenticationContexts data cleared and identity reset';
    END
    ELSE
        PRINT '✓ AuthenticationContexts already empty';

    -- Membership Tables
    IF EXISTS (SELECT 1 FROM dbo.Memberships)
    BEGIN
        DELETE FROM dbo.Memberships;
        INSERT INTO @DeletedRows VALUES ('Memberships', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.Memberships', RESEED, 0);
        PRINT '✓ Memberships data cleared and identity reset';
    END
    ELSE
        PRINT '✓ Memberships already empty';

    -- OTP Management Tables
    IF EXISTS (SELECT 1 FROM dbo.FailedOtpAttempts)
    BEGIN
        DELETE FROM dbo.FailedOtpAttempts;
        INSERT INTO @DeletedRows VALUES ('FailedOtpAttempts', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.FailedOtpAttempts', RESEED, 0);
        PRINT '✓ FailedOtpAttempts data cleared and identity reset';
    END
    ELSE
        PRINT '✓ FailedOtpAttempts already empty';

    IF EXISTS (SELECT 1 FROM dbo.OtpRecords)
    BEGIN
        DELETE FROM dbo.OtpRecords;
        INSERT INTO @DeletedRows VALUES ('OtpRecords', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.OtpRecords', RESEED, 0);
        PRINT '✓ OtpRecords data cleared and identity reset';
    END
    ELSE
        PRINT '✓ OtpRecords already empty';

    -- Verification Tables
    IF EXISTS (SELECT 1 FROM dbo.VerificationFlows)
    BEGIN
        DELETE FROM dbo.VerificationFlows;
        INSERT INTO @DeletedRows VALUES ('VerificationFlows', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.VerificationFlows', RESEED, 0);
        PRINT '✓ VerificationFlows data cleared and identity reset';
    END
    ELSE
        PRINT '✓ VerificationFlows already empty';

    -- Phone Number Management Tables
    IF EXISTS (SELECT 1 FROM dbo.PhoneNumberDevices)
    BEGIN
        DELETE FROM dbo.PhoneNumberDevices;
        INSERT INTO @DeletedRows VALUES ('PhoneNumberDevices', @@ROWCOUNT, GETUTCDATE());
        PRINT '✓ PhoneNumberDevices data cleared';
    END
    ELSE
        PRINT '✓ PhoneNumberDevices already empty';

    IF EXISTS (SELECT 1 FROM dbo.PhoneNumbers)
    BEGIN
        DELETE FROM dbo.PhoneNumbers;
        INSERT INTO @DeletedRows VALUES ('PhoneNumbers', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.PhoneNumbers', RESEED, 0);
        PRINT '✓ PhoneNumbers data cleared and identity reset';
    END
    ELSE
        PRINT '✓ PhoneNumbers already empty';

    -- Device Management Tables (Base tables)
    IF EXISTS (SELECT 1 FROM dbo.AppDevices)
    BEGIN
        DELETE FROM dbo.AppDevices;
        INSERT INTO @DeletedRows VALUES ('AppDevices', @@ROWCOUNT, GETUTCDATE());
        DBCC CHECKIDENT ('dbo.AppDevices', RESEED, 0);
        PRINT '✓ AppDevices data cleared and identity reset';
    END
    ELSE
        PRINT '✓ AppDevices already empty';

    PRINT '';

    -- ============================================================================
    -- STEP 3: RE-ENABLE FOREIGN KEY CONSTRAINTS
    -- ============================================================================

    PRINT 'Step 3: Re-enabling foreign key constraints...';

    -- Re-enable all foreign key constraints
    EXEC sp_MSforeachtable 'ALTER TABLE ? WITH CHECK CHECK CONSTRAINT ALL';

    -- Validate all constraints
    DECLARE @ConstraintErrors INT = 0;

    -- Check for constraint violations
    EXEC sp_MSforeachtable '
        BEGIN TRY
            ALTER TABLE ? CHECK CONSTRAINT ALL;
        END TRY
        BEGIN CATCH
            PRINT ''⚠️  Constraint error in table: ?'';
            SELECT @ConstraintErrors = @ConstraintErrors + 1;
        END CATCH
    ', @ConstraintErrors OUTPUT;

    IF @ConstraintErrors = 0
        PRINT '✓ All foreign key constraints re-enabled and validated';
    ELSE
        PRINT '⚠️  ' + CAST(@ConstraintErrors AS NVARCHAR(10)) + ' constraint validation errors found';

    PRINT '';

    -- ============================================================================
    -- STEP 4: CLEANUP SUMMARY AND VERIFICATION
    -- ============================================================================

    PRINT 'Step 4: Cleanup summary and verification...';

    -- Display cleanup summary
    PRINT 'Cleanup Summary:';
    PRINT '================';

    DECLARE @TotalRowsDeleted INT = 0;

    SELECT @TotalRowsDeleted = SUM(RowCount) FROM @DeletedRows;

    -- Display detailed results
    IF EXISTS (SELECT 1 FROM @DeletedRows)
    BEGIN
        SELECT
            TableName,
            RowCount AS [Rows Deleted],
            FORMAT(CleanupTime, 'yyyy-MM-dd HH:mm:ss') AS [Cleanup Time]
        FROM @DeletedRows
        ORDER BY TableName;
    END

    PRINT '';
    PRINT 'Total rows deleted: ' + CAST(ISNULL(@TotalRowsDeleted, 0) AS NVARCHAR(10));

    -- Verify tables are empty (except system logs)
    DECLARE @VerificationResults TABLE (
        TableName NVARCHAR(255),
        RowCount INT
    );

    INSERT INTO @VerificationResults
    SELECT 'AppDevices', COUNT(*) FROM dbo.AppDevices
    UNION ALL
    SELECT 'PhoneNumbers', COUNT(*) FROM dbo.PhoneNumbers
    UNION ALL
    SELECT 'PhoneNumberDevices', COUNT(*) FROM dbo.PhoneNumberDevices
    UNION ALL
    SELECT 'VerificationFlows', COUNT(*) FROM dbo.VerificationFlows
    UNION ALL
    SELECT 'OtpRecords', COUNT(*) FROM dbo.OtpRecords
    UNION ALL
    SELECT 'FailedOtpAttempts', COUNT(*) FROM dbo.FailedOtpAttempts
    UNION ALL
    SELECT 'Memberships', COUNT(*) FROM dbo.Memberships
    UNION ALL
    SELECT 'AuthenticationContexts', COUNT(*) FROM dbo.AuthenticationContexts
    UNION ALL
    SELECT 'AuthenticationStates', COUNT(*) FROM dbo.AuthenticationStates
    UNION ALL
    SELECT 'LoginAttempts', COUNT(*) FROM dbo.LoginAttempts
    UNION ALL
    SELECT 'MembershipAttempts', COUNT(*) FROM dbo.MembershipAttempts;

    DECLARE @TablesWithData INT;
    SELECT @TablesWithData = COUNT(*) FROM @VerificationResults WHERE RowCount > 0;

    IF @TablesWithData = 0
    BEGIN
        PRINT '✅ Verification PASSED: All business tables are empty';
    END
    ELSE
    BEGIN
        PRINT '⚠️  Verification WARNING: ' + CAST(@TablesWithData AS NVARCHAR(10)) + ' tables still contain data:';
        SELECT TableName, RowCount FROM @VerificationResults WHERE RowCount > 0;
    END

    -- Log successful completion
    INSERT INTO dbo.EventLog (EventType, Message)
    VALUES ('SYSTEM', 'Database cleanup completed successfully at ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121) +
                     '. Total rows deleted: ' + CAST(ISNULL(@TotalRowsDeleted, 0) AS NVARCHAR(10)));

    COMMIT TRANSACTION DataCleanup;

    PRINT '';
    PRINT '================================================================================';
    PRINT '✅ Database Data Cleanup Completed Successfully!';
    PRINT 'Finished at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
    PRINT '================================================================================';

END TRY
BEGIN CATCH
    -- Rollback on error
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION DataCleanup;

    -- Re-enable constraints even on error
    BEGIN TRY
        EXEC sp_MSforeachtable 'ALTER TABLE ? WITH CHECK CHECK CONSTRAINT ALL';
    END TRY
    BEGIN CATCH
        PRINT '⚠️  Warning: Could not re-enable all constraints after error';
    END CATCH

    -- Log the error
    INSERT INTO dbo.EventLog (EventType, Message)
    VALUES ('ERROR', 'Database cleanup failed at ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121) +
                    '. Error: ' + ERROR_MESSAGE());

    -- Display error information
    PRINT '';
    PRINT '================================================================================';
    PRINT '❌ Database Cleanup Failed!';
    PRINT 'Error Number: ' + CAST(ERROR_NUMBER() AS NVARCHAR(10));
    PRINT 'Error Message: ' + ERROR_MESSAGE();
    PRINT 'Error Line: ' + CAST(ERROR_LINE() AS NVARCHAR(10));
    PRINT 'All changes have been rolled back.';
    PRINT '================================================================================';

    -- Re-throw the error
    THROW;
END CATCH
GO

PRINT '';
PRINT 'Script execution completed. Check messages above for results.';
PRINT 'Remember to backup your database before running cleanup scripts in production!';
GO