/*
================================================================================
Layer 1.3: Validation Framework
================================================================================
Purpose: Core validation functions and procedures for data integrity
Dependencies: 01_SystemConfiguration.sql, 02_LoggingInfrastructure.sql
Execution Order: 4th - Foundation validation layer for all data operations

Features:
- Phone number validation with international formats
- IP address validation (IPv4/IPv6)
- GUID/UUID validation
- Input sanitization procedures
- Data type validation functions
- Business rule validation framework

Author: Ecliptix Development Team
Version: 1.0.0
Created: 2024-08-24
================================================================================
*/

USE [memberships];

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Layer 1.3: Validation Framework';
PRINT 'Started at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
PRINT '================================================================================';

-- Log deployment start
DECLARE @DeploymentId UNIQUEIDENTIFIER = (
    SELECT TOP 1 DeploymentId
    FROM dbo.DeploymentLog 
    WHERE Status = 'COMPLETED' 
    ORDER BY CreatedAt DESC
);

DECLARE @LogId BIGINT;
DECLARE @LogIdTable TABLE (Id BIGINT);

INSERT INTO dbo.DeploymentLog (DeploymentId, ScriptName, ExecutionOrder, Status)
OUTPUT INSERTED.Id INTO @LogIdTable
VALUES (@DeploymentId, '03_ValidationFramework.sql', 3, 'RUNNING');

SELECT TOP 1 @LogId = Id FROM @LogIdTable;

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- PHONE NUMBER VALIDATION
    -- ============================================================================
    
    PRINT 'Creating phone number validation function...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.ValidatePhoneNumber', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.ValidatePhoneNumber;
    
    -- Enhanced phone number validation function
        CREATE FUNCTION dbo.ValidatePhoneNumber(@PhoneNumber NVARCHAR(20))
    RETURNS BIT
    AS
    BEGIN
        DECLARE @IsValid BIT = 0;
        DECLARE @CleanedNumber NVARCHAR(20);

        -- Input validation
        IF @PhoneNumber IS NULL OR LEN(TRIM(@PhoneNumber)) = 0
            RETURN 0;

        -- Remove common formatting characters
        SET @CleanedNumber = REPLACE(REPLACE(REPLACE(REPLACE(@PhoneNumber, ' ', ''), '(', ''), ')', ''), '-', '');
        SET @CleanedNumber = REPLACE(REPLACE(@CleanedNumber, '.', ''), '+', '');

        -- Check if contains only digits after cleaning
        IF @CleanedNumber NOT LIKE '%[^0-9]%'
        BEGIN
            -- Length validation (7-15 digits for international numbers)
            DECLARE @Length INT = LEN(@CleanedNumber);
            IF @Length >= 7 AND @Length <= 15
            BEGIN
                -- Additional business rules
                -- Reject numbers starting with 0 or 1 (invalid for many regions)
                IF LEFT(@CleanedNumber, 1) NOT IN ('0', '1')
                    SET @IsValid = 1;
                -- Exception: Allow numbers starting with 1 if length is 10-11 (North America)
                ELSE IF LEFT(@CleanedNumber, 1) = '1' AND @Length IN (10, 11)
                    SET @IsValid = 1;
            END
        END

        RETURN @IsValid;
    END;
    
    PRINT '✓ ValidatePhoneNumber function created successfully';
    
    -- ============================================================================
    -- IP ADDRESS VALIDATION
    -- ============================================================================
    PRINT 'Creating IP address validation function...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.ValidateIpAddress', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.ValidateIpAddress;
    
    -- IP address validation function (IPv4 and basic IPv6)
        CREATE FUNCTION dbo.ValidateIpAddress(@IpAddress NVARCHAR(45))
    RETURNS BIT
    AS
    BEGIN
        DECLARE @IsValid BIT = 0;

        -- Input validation
        IF @IpAddress IS NULL OR LEN(TRIM(@IpAddress)) = 0
            RETURN 0;

        SET @IpAddress = LTRIM(RTRIM(@IpAddress));

        -- IPv4 validation
        IF CHARINDEX(':', @IpAddress) = 0
        BEGIN
            -- Split IPv4 into octets
            DECLARE @Octet1 INT, @Octet2 INT, @Octet3 INT, @Octet4 INT;
            DECLARE @DotCount INT = LEN(@IpAddress) - LEN(REPLACE(@IpAddress, '.', ''));

            IF @DotCount = 3
            BEGIN
                -- Extract octets
                DECLARE @Pos1 INT = CHARINDEX('.', @IpAddress);
                DECLARE @Pos2 INT = CHARINDEX('.', @IpAddress, @Pos1 + 1);
                DECLARE @Pos3 INT = CHARINDEX('.', @IpAddress, @Pos2 + 1);

                IF @Pos1 > 0 AND @Pos2 > 0 AND @Pos3 > 0
                BEGIN
                    -- Use ISNUMERIC to check conversion
                    IF ISNUMERIC(LEFT(@IpAddress, @Pos1 - 1)) = 1 AND
                       ISNUMERIC(SUBSTRING(@IpAddress, @Pos1 + 1, @Pos2 - @Pos1 - 1)) = 1 AND
                       ISNUMERIC(SUBSTRING(@IpAddress, @Pos2 + 1, @Pos3 - @Pos2 - 1)) = 1 AND
                       ISNUMERIC(SUBSTRING(@IpAddress, @Pos3 + 1, LEN(@IpAddress) - @Pos3)) = 1
                    BEGIN
                        SET @Octet1 = CAST(LEFT(@IpAddress, @Pos1 - 1) AS INT);
                        SET @Octet2 = CAST(SUBSTRING(@IpAddress, @Pos1 + 1, @Pos2 - @Pos1 - 1) AS INT);
                        SET @Octet3 = CAST(SUBSTRING(@IpAddress, @Pos2 + 1, @Pos3 - @Pos2 - 1) AS INT);
                        SET @Octet4 = CAST(SUBSTRING(@IpAddress, @Pos3 + 1, LEN(@IpAddress) - @Pos3) AS INT);

                        -- Validate octet ranges
                        IF @Octet1 BETWEEN 0 AND 255 AND
                           @Octet2 BETWEEN 0 AND 255 AND
                           @Octet3 BETWEEN 0 AND 255 AND
                           @Octet4 BETWEEN 0 AND 255
                            SET @IsValid = 1;
                    END
                END
            END
        END
        -- Basic IPv6 validation (simplified)
        ELSE IF CHARINDEX(':', @IpAddress) > 0
        BEGIN
            -- Basic IPv6 format check
            DECLARE @ColonCount INT = LEN(@IpAddress) - LEN(REPLACE(@IpAddress, ':', ''));
            DECLARE @DoubleColonCount INT = (LEN(@IpAddress) - LEN(REPLACE(@IpAddress, '::', ''))) / 2;

            -- IPv6 should have 2-8 colons, and at most one double colon
            IF @ColonCount >= 2 AND @ColonCount <= 8 AND @DoubleColonCount <= 1
            BEGIN
                -- Check for valid hexadecimal characters
                DECLARE @HexCheck NVARCHAR(45) = REPLACE(REPLACE(@IpAddress, ':', ''), '.', '');
                IF @HexCheck NOT LIKE '%[^0-9a-fA-F]%'
                    SET @IsValid = 1;
            END
        END

        RETURN @IsValid;
    END;
    
    PRINT '✓ ValidateIpAddress function created successfully';
    
    -- ============================================================================
    -- GUID VALIDATION
    -- ============================================================================

    PRINT 'Creating GUID validation function...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.ValidateGuid', 'FN') IS NOT NULL 
        DROP FUNCTION dbo.ValidateGuid;
    
    -- GUID validation function
        CREATE FUNCTION dbo.ValidateGuid(@GuidValue NVARCHAR(50))
    RETURNS BIT
    AS
    BEGIN
        DECLARE @IsValid BIT = 0;

        -- Input validation
        IF @GuidValue IS NULL OR LEN(TRIM(@GuidValue)) = 0
            RETURN 0;
        
        SET @GuidValue = LTRIM(RTRIM(@GuidValue));
        
        -- Remove braces if present
        IF LEFT(@GuidValue, 1) = '{' AND RIGHT(@GuidValue, 1) = '}'
            SET @GuidValue = SUBSTRING(@GuidValue, 2, LEN(@GuidValue) - 2);
        
        -- Check GUID format: 8-4-4-4-12 hexadecimal digits
        IF LEN(@GuidValue) = 36 AND
           SUBSTRING(@GuidValue, 9, 1) = '-' AND
           SUBSTRING(@GuidValue, 14, 1) = '-' AND
           SUBSTRING(@GuidValue, 19, 1) = '-' AND
           SUBSTRING(@GuidValue, 24, 1) = '-'
        BEGIN
            -- Remove dashes and check for valid hex characters
            DECLARE @HexOnly NVARCHAR(32) = REPLACE(@GuidValue, '-', '');
            IF @HexOnly NOT LIKE '%[^0-9a-fA-F]%'
            BEGIN
                SET @IsValid = 1;
            END
        END

        RETURN @IsValid;
    END;
    
    PRINT '✓ ValidateGuid function created successfully';
    
    -- ============================================================================
    -- INPUT SANITIZATION PROCEDURES
    -- ============================================================================
    
    PRINT 'Creating input sanitization procedures...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.SanitizeInput', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.SanitizeInput;
    
    -- Input sanitization procedure
        CREATE PROCEDURE dbo.SanitizeInput
        @Input NVARCHAR(MAX),
        @MaxLength INT = 255,
        @AllowSpecialChars BIT = 0,
        @SanitizedOutput NVARCHAR(MAX) OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        -- Initialize output
        SET @SanitizedOutput = ISNULL(@Input, '');
        
        -- Trim whitespace
        SET @SanitizedOutput = LTRIM(RTRIM(@SanitizedOutput));
        
        -- Remove or escape potentially dangerous characters
        IF @AllowSpecialChars = 0
        BEGIN
            -- Remove SQL injection patterns
            SET @SanitizedOutput = REPLACE(@SanitizedOutput, '''', '');
            SET @SanitizedOutput = REPLACE(@SanitizedOutput, '--', '');
            SET @SanitizedOutput = REPLACE(@SanitizedOutput, '/*', '');
            SET @SanitizedOutput = REPLACE(@SanitizedOutput, '*/', '');
            SET @SanitizedOutput = REPLACE(@SanitizedOutput, 'xp_', '');
            SET @SanitizedOutput = REPLACE(@SanitizedOutput, 'sp_', '');
            
            -- Remove HTML/XML tags
            WHILE CHARINDEX('<', @SanitizedOutput) > 0 AND CHARINDEX('>', @SanitizedOutput) > CHARINDEX('<', @SanitizedOutput)
            BEGIN
                DECLARE @StartPos INT = CHARINDEX('<', @SanitizedOutput);
                DECLARE @EndPos INT = CHARINDEX('>', @SanitizedOutput, @StartPos);
                SET @SanitizedOutput = LEFT(@SanitizedOutput, @StartPos - 1) + SUBSTRING(@SanitizedOutput, @EndPos + 1, LEN(@SanitizedOutput));
            END
        END
        
        -- Enforce maximum length
        IF LEN(@SanitizedOutput) > @MaxLength
            SET @SanitizedOutput = LEFT(@SanitizedOutput, @MaxLength);
        
        -- Log sanitization if significant changes were made
        IF @Input != @SanitizedOutput AND LEN(@Input) > 0
        BEGIN
            EXEC dbo.LogAuditEvent 
                @EventType = 'INPUT_SANITIZATION',
                @Details = 'Input sanitized: length reduced or dangerous characters removed',
                @UserId = NULL,
                @IpAddress = NULL;
        END
    END;
    
    PRINT '✓ SanitizeInput procedure created successfully';
    
    -- ============================================================================
    -- BUSINESS RULE VALIDATION FRAMEWORK
    -- ============================================================================
    
    PRINT 'Creating business rule validation framework...';
    
    -- Drop existing if exists
    IF OBJECT_ID('dbo.ValidateBusinessRules', 'P') IS NOT NULL 
        DROP PROCEDURE dbo.ValidateBusinessRules;

    -- Business rule validation procedure
        CREATE PROCEDURE dbo.ValidateBusinessRules
        @EntityType NVARCHAR(50),
        @EntityData NVARCHAR(MAX),
        @ValidationContext NVARCHAR(100) = NULL,
        @IsValid BIT OUTPUT,
        @ValidationErrors NVARCHAR(MAX) OUTPUT
    AS
    BEGIN
        SET NOCOUNT ON;
        
        DECLARE @ErrorList TABLE (ErrorMessage NVARCHAR(255));
        SET @IsValid = 1;
        SET @ValidationErrors = '';
        
        -- Phone Number validations
        IF @EntityType = 'PhoneNumber'
        BEGIN
            -- Validate phone number format
            IF dbo.ValidatePhoneNumber(@EntityData) = 0
            BEGIN
                INSERT INTO @ErrorList VALUES ('Invalid phone number format');
                SET @IsValid = 0;
            END
            
            -- Check for prohibited patterns (example: no test numbers)
            IF @EntityData LIKE '%1234567890%' OR @EntityData LIKE '%0000000000%'
            BEGIN
                INSERT INTO @ErrorList VALUES ('Phone number appears to be a test number');
                SET @IsValid = 0;
            END
            
            -- Rate limiting validation for certain contexts
            IF @ValidationContext = 'VERIFICATION_REQUEST'
            BEGIN
                DECLARE @RecentFlows INT;
                DECLARE @MaxFlowsPerHour INT = CAST(dbo.GetConfigValue('RateLimit.MaxFlowsPerHour') AS INT);

                SELECT @RecentFlows = COUNT(*)
                FROM dbo.VerificationFlows vf
                INNER JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
                WHERE pn.PhoneNumber = @EntityData
                  AND vf.CreatedAt >= DATEADD(HOUR, -1, GETUTCDATE());

                IF @RecentFlows >= @MaxFlowsPerHour
                BEGIN
                    INSERT INTO @ErrorList VALUES ('Too many verification attempts. Please try again later.');
                    SET @IsValid = 0;
                END
            END
        END
        
        -- Membership validations
        ELSE IF @EntityType = 'Membership'
        BEGIN
            -- Parse JSON-like data (simplified example)
            DECLARE @PhoneNumber NVARCHAR(20) = JSON_VALUE(@EntityData, '$.PhoneNumber');
            DECLARE @DeviceId NVARCHAR(50) = JSON_VALUE(@EntityData, '$.DeviceId');
            
            -- Validate phone number if provided
            IF @PhoneNumber IS NOT NULL AND dbo.ValidatePhoneNumber(@PhoneNumber) = 0
            BEGIN
                INSERT INTO @ErrorList VALUES ('Invalid phone number in membership data');
                SET @IsValid = 0;
            END
            
            -- Validate device ID if provided
            IF @DeviceId IS NOT NULL AND dbo.ValidateGuid(@DeviceId) = 0
            BEGIN
                INSERT INTO @ErrorList VALUES ('Invalid device ID format');
                SET @IsValid = 0;
            END
        END
        
        -- Compile error messages
        SELECT @ValidationErrors = COALESCE(@ValidationErrors + '; ', '') + ErrorMessage
        FROM @ErrorList;
        
        -- Log validation results if there were errors
        IF @IsValid = 0
        BEGIN
            EXEC dbo.LogAuditEvent 
                @EventType = 'VALIDATION_FAILED',
                @Details = @ValidationErrors,
                @AdditionalData = @EntityData;
        END
    END;
    
    PRINT '✓ ValidateBusinessRules procedure created successfully';
    
    -- ============================================================================
    -- VALIDATION FRAMEWORK TESTING
    -- ============================================================================
    
    PRINT 'Testing validation framework...';
    
    -- Test phone number validation
    DECLARE @TestResults TABLE (TestName NVARCHAR(100), Expected BIT, Actual BIT, Passed BIT);
    
    INSERT INTO @TestResults (TestName, Expected, Actual)
    VALUES 
        ('Valid US Phone', 1, dbo.ValidatePhoneNumber('+1234567890')),
        ('Valid International', 1, dbo.ValidatePhoneNumber('447123456789')),
        ('Invalid Short', 0, dbo.ValidatePhoneNumber('123')),
        ('Invalid Long', 0, dbo.ValidatePhoneNumber('123456789012345678')),
        ('Invalid Characters', 0, dbo.ValidatePhoneNumber('123-456-ABCD')),
        ('Valid IP v4', 1, dbo.ValidateIpAddress('192.168.1.1')),
        ('Invalid IP v4', 0, dbo.ValidateIpAddress('256.1.1.1')),
        ('Valid GUID', 1, dbo.ValidateGuid('12345678-1234-1234-1234-123456789012')),
        ('Invalid GUID', 0, dbo.ValidateGuid('invalid-guid-format'));
    
    UPDATE @TestResults
        SET Passed = CASE WHEN Expected = Actual THEN 1 ELSE 0 END
        WHERE Expected IS NOT NULL
          AND Actual IS NOT NULL;
    
    DECLARE @PassedTests INT, @TotalTests INT;
    SELECT @PassedTests = COUNT(*), @TotalTests = COUNT(*) FROM @TestResults WHERE Passed = 1;
    SELECT @TotalTests = COUNT(*) FROM @TestResults;
    
    IF @PassedTests = @TotalTests
        PRINT '✓ All validation tests passed (' + CAST(@PassedTests AS NVARCHAR(10)) + '/' + CAST(@TotalTests AS NVARCHAR(10)) + ')';
    ELSE
    BEGIN
        PRINT '⚠ Some validation tests failed (' + CAST(@PassedTests AS NVARCHAR(10)) + '/' + CAST(@TotalTests AS NVARCHAR(10)) + ')';
        SELECT TestName, Expected, Actual FROM @TestResults WHERE Passed = 0;
    END
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = @TotalTests
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 1.3: Validation Framework Completed Successfully';
    PRINT 'Validation functions: 3 (Phone, IP, GUID)';
    PRINT 'Validation procedures: 2 (Sanitize, BusinessRules)';
    PRINT 'Test results: ' + CAST(@PassedTests AS NVARCHAR(10)) + '/' + CAST(@TotalTests AS NVARCHAR(10));
    PRINT 'Next: Layer 1.4 - Utility Functions & Helpers';
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
    PRINT 'ERROR in Layer 1.3: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO