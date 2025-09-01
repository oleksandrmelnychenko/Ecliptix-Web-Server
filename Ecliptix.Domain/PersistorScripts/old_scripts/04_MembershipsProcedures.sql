-- mssql_membership_procedures_final.sql

-- Починаємо транзакцію
BEGIN TRANSACTION;
GO

-- Видалення існуючих процедур, щоб уникнути конфліктів
IF OBJECT_ID('dbo.CreateMembership', 'P') IS NOT NULL DROP PROCEDURE dbo.CreateMembership;
IF OBJECT_ID('dbo.UpdateMembershipSecureKey', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateMembershipSecureKey;
IF OBJECT_ID('dbo.LoginMembership', 'P') IS NOT NULL DROP PROCEDURE dbo.LoginMembership;
IF OBJECT_ID('dbo.LogLoginAttempt', 'P') IS NOT NULL DROP PROCEDURE dbo.LogLoginAttempt;
IF OBJECT_ID('dbo.LogMembershipAttempt', 'P') IS NOT NULL DROP PROCEDURE dbo.LogMembershipAttempt;
GO

-- Зробити колонку SecureKey nullable, якщо вона ще не така
IF EXISTS (SELECT 1 FROM sys.columns WHERE Name = N'SecureKey' AND Object_ID = Object_ID(N'dbo.Memberships') AND is_nullable = 0)
BEGIN
    ALTER TABLE dbo.Memberships ALTER COLUMN SecureKey VARBINARY(MAX) NULL;
    PRINT 'Altered column SecureKey in Memberships to be nullable.';
END;
GO

--------------------------------------------------------------------------------
-- Процедура: LogLoginAttempt
-- Призначення: Логує спробу входу.
--------------------------------------------------------------------------------
CREATE OR ALTER PROCEDURE dbo.LogLoginAttempt
    @PhoneNumber NVARCHAR(18),
    @Outcome NVARCHAR(MAX),
    @IsSuccess BIT
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.LoginAttempts (Timestamp, PhoneNumber, Outcome, IsSuccess)
    VALUES (GETUTCDATE(), @PhoneNumber, @Outcome, @IsSuccess);
END;
GO

--------------------------------------------------------------------------------
-- Процедура: LogMembershipAttempt
-- Призначення: Логує спробу створення членства.
--------------------------------------------------------------------------------
CREATE OR ALTER PROCEDURE dbo.LogMembershipAttempt
    @PhoneNumberId UNIQUEIDENTIFIER,
    @Outcome NVARCHAR(MAX),
    @IsSuccess BIT
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.MembershipAttempts (PhoneNumberId, Timestamp, Outcome, IsSuccess)
    VALUES (@PhoneNumberId, GETUTCDATE(), @Outcome, @IsSuccess);
END;
GO

--------------------------------------------------------------------------------
-- Процедура: CreateMembership
-- Призначення: Створює нове членство з обмеженням спроб.
--------------------------------------------------------------------------------
CREATE OR ALTER PROCEDURE dbo.CreateMembership
    @FlowUniqueId UNIQUEIDENTIFIER,
    @ConnectionId BIGINT,
    @OtpUniqueId UNIQUEIDENTIFIER,
    @CreationStatus NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @MembershipUniqueId UNIQUEIDENTIFIER;
    DECLARE @Status NVARCHAR(20);
    DECLARE @Outcome NVARCHAR(100);

    DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
    DECLARE @AppDeviceId UNIQUEIDENTIFIER;
    DECLARE @ExistingMembershipId BIGINT;
    DECLARE @ExistingCreationStatus NVARCHAR(20);

    DECLARE @FailedAttempts INT;
    DECLARE @AttemptWindowHours INT = 1;
    DECLARE @MaxAttempts INT = 5;
    DECLARE @EarliestFailedAttempt DATETIME2(7);
    DECLARE @WaitMinutes INT;

    SELECT @PhoneNumberId = pn.UniqueId
    FROM dbo.VerificationFlows vf
    JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
    WHERE vf.UniqueId = @FlowUniqueId AND vf.IsDeleted = 0;

    -- Перевірка обмеження спроб (rate limiting)
    SELECT
        @FailedAttempts = COUNT(*),
        @EarliestFailedAttempt = MIN(Timestamp)
    FROM dbo.MembershipAttempts
    WHERE PhoneNumberId = @PhoneNumberId
      AND IsSuccess = 0
      AND Timestamp > DATEADD(hour, -@AttemptWindowHours, GETUTCDATE())
    OPTION (MAXRECURSION 100);

    IF @FailedAttempts >= @MaxAttempts
    BEGIN
        SET @WaitMinutes = DATEDIFF(minute, GETUTCDATE(), DATEADD(hour, @AttemptWindowHours, @EarliestFailedAttempt));
        SET @Outcome = CAST(CASE WHEN @WaitMinutes < 0 THEN 0 ELSE @WaitMinutes END AS NVARCHAR(100));
        EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 0;
        SELECT NULL AS MembershipUniqueId, NULL AS Status, @CreationStatus AS CreationStatus, @Outcome AS Outcome;
        RETURN;
    END

    -- Отримуємо деталі сесії
    SELECT
        @PhoneNumberId = pn.UniqueId,
        @AppDeviceId = vf.AppDeviceId
    FROM dbo.VerificationFlows vf
    JOIN dbo.PhoneNumbers pn ON vf.PhoneNumberId = pn.Id
    WHERE vf.UniqueId = @FlowUniqueId
      AND vf.ConnectionId = @ConnectionId
      AND vf.Purpose = 'registration'
      AND vf.IsDeleted = 0
      AND pn.IsDeleted = 0;

    IF @@ROWCOUNT = 0
    BEGIN
        SET @Outcome = 'verification_flow_not_found';
        -- Логуємо тільки якщо ми змогли отримати PhoneNumberId раніше
        IF @PhoneNumberId IS NOT NULL EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 0;
        SELECT NULL AS MembershipUniqueId, NULL AS Status, NULL AS CreationStatus, @Outcome AS Outcome;
        RETURN;
    END

    -- Перевірка на існування членства
    SELECT TOP 1
        @ExistingMembershipId = Id,
        @MembershipUniqueId = UniqueId,
        @Status = Status,
        @ExistingCreationStatus = CreationStatus
    FROM dbo.Memberships
    WHERE PhoneNumberId = @PhoneNumberId AND AppDeviceId = @AppDeviceId AND IsDeleted = 0;

    IF @ExistingMembershipId IS NOT NULL
    BEGIN
        SET @Outcome = 'membership_already_exists';
        EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 1;
        SELECT @MembershipUniqueId AS MembershipUniqueId, @Status AS Status, @ExistingCreationStatus AS CreationStatus, @Outcome AS Outcome;
        RETURN;
    END

    -- Створення нового членства
    DECLARE @OutputTable TABLE (UniqueId UNIQUEIDENTIFIER, Status NVARCHAR(20), CreationStatus NVARCHAR(20));

    INSERT INTO dbo.Memberships (PhoneNumberId, AppDeviceId, VerificationFlowId, Status, CreationStatus)
    OUTPUT inserted.UniqueId, inserted.Status, inserted.CreationStatus INTO @OutputTable
    VALUES (@PhoneNumberId, @AppDeviceId, @FlowUniqueId, 'active', @CreationStatus);

    SELECT @MembershipUniqueId = UniqueId, @Status = Status, @CreationStatus = CreationStatus FROM @OutputTable;

    UPDATE dbo.OtpRecords SET IsActive = 0 WHERE UniqueId = @OtpUniqueId AND FlowUniqueId = @FlowUniqueId;

    SET @Outcome = 'created';
    EXEC dbo.LogMembershipAttempt @PhoneNumberId, @Outcome, 1;

    DELETE FROM dbo.MembershipAttempts WHERE PhoneNumberId = @PhoneNumberId AND IsSuccess = 0;

    SELECT @MembershipUniqueId AS MembershipUniqueId, @Status AS Status, @CreationStatus AS CreationStatus, @Outcome AS Outcome;
END;
GO

--------------------------------------------------------------------------------
-- Процедура: UpdateMembershipSecureKey
-- Призначення: Оновлює SecureKey для існуючого членства.
--------------------------------------------------------------------------------
CREATE OR ALTER PROCEDURE dbo.UpdateMembershipSecureKey
    @MembershipUniqueId UNIQUEIDENTIFIER,
    @SecureKey VARBINARY(MAX)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
    DECLARE @CurrentStatus NVARCHAR(20), @CurrentCreationStatus NVARCHAR(20);

    IF @SecureKey IS NULL OR DATALENGTH(@SecureKey) = 0
    BEGIN
        SELECT 0 AS Success, 'Secure key cannot be empty' AS Message, NULL AS MembershipUniqueId, NULL AS Status, NULL AS CreationStatus;
        RETURN;
    END

    SELECT @PhoneNumberId = PhoneNumberId
    FROM dbo.Memberships
    WHERE UniqueId = @MembershipUniqueId AND IsDeleted = 0;

    IF @@ROWCOUNT = 0
    BEGIN
        -- Немає сенсу логувати, якщо ми не знаємо PhoneNumberId
        SELECT 0 AS Success, 'Membership not found or deleted' AS Message, NULL AS MembershipUniqueId, NULL AS Status, NULL AS CreationStatus;
        RETURN;
    END

    UPDATE dbo.Memberships
    SET SecureKey = @SecureKey,
        Status = 'active',
        CreationStatus = 'secure_key_set'
    WHERE UniqueId = @MembershipUniqueId;

    IF @@ROWCOUNT = 0
    BEGIN
        EXEC dbo.LogMembershipAttempt @PhoneNumberId, 'update_failed', 0;
        SELECT 0 AS Success, 'Failed to update membership' AS Message, NULL AS MembershipUniqueId, NULL AS Status, NULL AS CreationStatus;
        RETURN;
    END

    SELECT @CurrentStatus = Status, @CurrentCreationStatus = CreationStatus FROM dbo.Memberships WHERE UniqueId = @MembershipUniqueId;
    EXEC dbo.LogMembershipAttempt @PhoneNumberId, 'secure_key_updated', 1;

    SELECT 1 AS Success, 'Secure key updated successfully' AS Message, @MembershipUniqueId AS MembershipUniqueId, @CurrentStatus AS Status, @CurrentCreationStatus AS CreationStatus;
END;
GO

--------------------------------------------------------------------------------
-- Procedure: LoginMembership
-- Purpose: Authenticates a user with lockout logic and returns SecureKey.
--------------------------------------------------------------------------------
CREATE OR ALTER PROCEDURE dbo.LoginMembership
    @PhoneNumber NVARCHAR(18)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @MembershipUniqueId UNIQUEIDENTIFIER, @Status NVARCHAR(20), @Outcome NVARCHAR(100);
    DECLARE @PhoneNumberId UNIQUEIDENTIFIER, @StoredSecureKey VARBINARY(MAX), @CreationStatus NVARCHAR(20);
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
    DECLARE @AttemptsInLast5Minutes INT;
    DECLARE @LockoutDurationMinutes INT = 5;
    DECLARE @MaxAttemptsInPeriod INT = 5;
    DECLARE @LockoutMarkerPrefix NVARCHAR(20) = 'LOCKED_UNTIL:';
    DECLARE @LockedUntilTs DATETIME2(7);
    DECLARE @LastLockoutInitTime DATETIME2(7);
    DECLARE @LockoutMarkerOutcome NVARCHAR(MAX);
    DECLARE @LockoutPattern NVARCHAR(30) = @LockoutMarkerPrefix + '%';

    -- 1. Check for active lockout
    SELECT TOP 1 @LockoutMarkerOutcome = Outcome, @LastLockoutInitTime = Timestamp
    FROM dbo.LoginAttempts
    WHERE PhoneNumber = @PhoneNumber AND Outcome LIKE @LockoutPattern
    ORDER BY Timestamp DESC
    OPTION (MAXRECURSION 100);

    IF @LockoutMarkerOutcome IS NOT NULL
    BEGIN
        BEGIN TRY
            SET @LockedUntilTs = CAST(SUBSTRING(@LockoutMarkerOutcome, LEN(@LockoutMarkerPrefix) + 1, 100) AS DATETIME2(7));
        END TRY
        BEGIN CATCH
            SET @LockedUntilTs = NULL;
        END CATCH

        IF @LockedUntilTs IS NOT NULL AND @CurrentTime < @LockedUntilTs
        BEGIN
            SET @Outcome = CAST(CEILING(CAST(DATEDIFF(second, @CurrentTime, @LockedUntilTs) AS DECIMAL) / 60.0) AS NVARCHAR(100));
            SELECT NULL AS MembershipUniqueId, NULL AS Status, @Outcome AS Outcome, NULL AS SecureKey;
            RETURN;
        END
        ELSE IF @LockedUntilTs IS NOT NULL AND @CurrentTime >= @LockedUntilTs
        BEGIN
            DELETE FROM dbo.LoginAttempts
            WHERE PhoneNumber = @PhoneNumber
            AND Timestamp <= @LastLockoutInitTime;
        END
    END

    -- 2. Count attempts in last 5 minutes (excluding lockout markers)
    SELECT @AttemptsInLast5Minutes = COUNT(*)
    FROM dbo.LoginAttempts
    WHERE PhoneNumber = @PhoneNumber
    AND Timestamp > DATEADD(minute, -5, @CurrentTime)
    AND Outcome NOT LIKE @LockoutPattern
    OPTION (MAXRECURSION 100);

    -- 3. Check if we already have 5 attempts in last 5 minutes
    IF @AttemptsInLast5Minutes >= @MaxAttemptsInPeriod
    BEGIN
        SET @LockedUntilTs = DATEADD(minute, @LockoutDurationMinutes, @CurrentTime);
        DECLARE @NewLockoutMarker NVARCHAR(MAX) = CONCAT(@LockoutMarkerPrefix, CONVERT(NVARCHAR(30), @LockedUntilTs, 127));
        EXEC dbo.LogLoginAttempt @PhoneNumber, @NewLockoutMarker, 0;
        SET @Outcome = CAST(@LockoutDurationMinutes AS NVARCHAR(100));
        SELECT NULL AS MembershipUniqueId, NULL AS Status, @Outcome AS Outcome, NULL AS SecureKey;
        RETURN;
    END

    -- 4. Login attempt logic
    IF @PhoneNumber IS NULL OR @PhoneNumber = ''
        SET @Outcome = 'phone_number_cannot_be_empty';
    ELSE
    BEGIN
        SELECT @PhoneNumberId = UniqueId
        FROM dbo.PhoneNumbers
        WHERE PhoneNumber = @PhoneNumber AND IsDeleted = 0;

        IF @PhoneNumberId IS NULL
            SET @Outcome = 'phone_number_not_found';
        ELSE
        BEGIN
            SELECT TOP 1 @MembershipUniqueId = UniqueId,
                        @StoredSecureKey = SecureKey,
                        @Status = Status,
                        @CreationStatus = CreationStatus
            FROM dbo.Memberships
            WHERE PhoneNumberId = @PhoneNumberId
            AND IsDeleted = 0
            ORDER BY CreatedAt DESC;

            IF @MembershipUniqueId IS NULL
                SET @Outcome = 'membership_not_found';
            ELSE IF @StoredSecureKey IS NULL
                SET @Outcome = 'secure_key_not_set';
            ELSE IF @Status != 'active'
                SET @Outcome = 'inactive_membership';
            ELSE
                SET @Outcome = 'success';
        END
    END

    -- 5. Handle result
    IF @Outcome = 'success'
    BEGIN
        EXEC dbo.LogLoginAttempt @PhoneNumber, @Outcome, 1;
        DELETE FROM dbo.LoginAttempts
        WHERE PhoneNumber = @PhoneNumber
        AND (IsSuccess = 0 OR Outcome LIKE @LockoutPattern);
        SELECT @MembershipUniqueId AS MembershipUniqueId,
               @Status AS Status,
               @Outcome AS Outcome,
               @StoredSecureKey AS SecureKey;
    END
    ELSE
    BEGIN
        EXEC dbo.LogLoginAttempt @PhoneNumber, @Outcome, 0;
        SELECT NULL AS MembershipUniqueId,
               NULL AS Status,
               @Outcome AS Outcome,
               NULL AS SecureKey;
    END
END;
GO

-- Завершення транзакції
COMMIT TRANSACTION;
GO

-- Підтвердження
PRINT '✅ Membership procedures created successfully.';
GO