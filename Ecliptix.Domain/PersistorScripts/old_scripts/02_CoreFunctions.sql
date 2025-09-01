-- mssql_core_procedures_and_functions.sql

-- Починаємо транзакцію
BEGIN TRANSACTION;
GO

-- Видалення існуючих об'єктів
IF OBJECT_ID('dbo.EnsurePhoneNumber', 'P') IS NOT NULL DROP PROCEDURE dbo.EnsurePhoneNumber;
IF OBJECT_ID('dbo.RegisterAppDeviceIfNotExists', 'P') IS NOT NULL DROP PROCEDURE dbo.RegisterAppDeviceIfNotExists;
IF OBJECT_ID('dbo.VerifyPhoneForSecretKeyRecovery', 'P') IS NOT NULL DROP PROCEDURE dbo.VerifyPhoneForSecretKeyRecovery;
IF OBJECT_ID('dbo.GetPhoneNumber', 'IF') IS NOT NULL DROP FUNCTION dbo.GetPhoneNumber;
GO

--------------------------------------------------------------------------------
-- Функція: GetPhoneNumber (Inline Table-Valued Function)
-- Призначення: Отримує деталі номеру телефону за його UniqueId.
--------------------------------------------------------------------------------
CREATE FUNCTION dbo.GetPhoneNumber
(
    @UniqueId UNIQUEIDENTIFIER
)
RETURNS TABLE
AS
RETURN
(
    SELECT pn.PhoneNumber, pn.Region
    FROM dbo.PhoneNumbers AS pn
    WHERE pn.UniqueId = @UniqueId AND pn.IsDeleted = 0
);
GO

--------------------------------------------------------------------------------
-- Процедура: RegisterAppDeviceIfNotExists
-- Призначення: Реєструє пристрій, якщо він ще не існує.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.RegisterAppDeviceIfNotExists
    @AppInstanceId UNIQUEIDENTIFIER,
    @DeviceId UNIQUEIDENTIFIER,
    @DeviceType INT
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @DeviceUniqueId UNIQUEIDENTIFIER;
    DECLARE @Status INT;

    -- Використовуємо блокування, щоб уникнути race condition
    SELECT @DeviceUniqueId = UniqueId
    FROM dbo.AppDevices WITH (UPDLOCK, HOLDLOCK)
    WHERE DeviceId = @DeviceId AND IsDeleted = 0;

    IF @DeviceUniqueId IS NOT NULL
    BEGIN
        -- 1 = Exists
        SET @Status = 1;
        SELECT @DeviceUniqueId AS UniqueId, @Status AS Status;
        RETURN;
    END
    ELSE
    BEGIN
        -- Пристрій не існує, спробуємо вставити
        INSERT INTO dbo.AppDevices (AppInstanceId, DeviceId, DeviceType)
        VALUES (@AppInstanceId, @DeviceId, @DeviceType);

        -- Отримуємо щойно створений UniqueId
        SELECT @DeviceUniqueId = UniqueId FROM dbo.AppDevices WHERE DeviceId = @DeviceId;

        -- 2 = Created
        SET @Status = 2;
        SELECT @DeviceUniqueId AS UniqueId, @Status AS Status;
        RETURN;
    END
END;
GO

--------------------------------------------------------------------------------
-- Процедура: EnsurePhoneNumber
-- Призначення: Створює номер телефону, якщо він не існує, та опціонально пов'язує його з пристроєм.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.EnsurePhoneNumber
    @PhoneNumberString NVARCHAR(18),
    @Region NVARCHAR(2),
    @AppDeviceId UNIQUEIDENTIFIER = NULL
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @PhoneUniqueId UNIQUEIDENTIFIER;
    DECLARE @Outcome NVARCHAR(50);
    DECLARE @Success BIT;
    DECLARE @Message NVARCHAR(255);

    -- Використовуємо блокування, щоб уникнути race condition при створенні/пошуку номеру
    SELECT @PhoneUniqueId = UniqueId
    FROM dbo.PhoneNumbers WITH (UPDLOCK, HOLDLOCK)
    WHERE PhoneNumber = @PhoneNumberString
      AND (Region = @Region OR (Region IS NULL AND @Region IS NULL))
      AND IsDeleted = 0;

    IF @PhoneUniqueId IS NOT NULL
    BEGIN
        -- Номер існує
        SET @Outcome = 'exists';
        SET @Success = 1;
        SET @Message = 'Phone number already exists.';

        IF @AppDeviceId IS NOT NULL
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM dbo.AppDevices WHERE UniqueId = @AppDeviceId AND IsDeleted = 0)
            BEGIN
                SELECT @PhoneUniqueId AS UniqueId, 'existing_but_invalid_app_device' AS Outcome, 0 AS Success, 'Phone exists, but provided AppDeviceId is invalid' AS Message;
                RETURN;
            END

            -- Емуляція ON CONFLICT DO UPDATE для зв'язку
            IF EXISTS (SELECT 1 FROM dbo.PhoneNumberDevices WHERE PhoneNumberId = @PhoneUniqueId AND AppDeviceId = @AppDeviceId)
            BEGIN
                -- Якщо зв'язок існує, оновлюємо його, якщо він був видалений
                UPDATE dbo.PhoneNumberDevices
                SET IsDeleted = 0, UpdatedAt = GETUTCDATE()
                WHERE PhoneNumberId = @PhoneUniqueId AND AppDeviceId = @AppDeviceId AND IsDeleted = 1;
            END
            ELSE
            BEGIN
                -- Якщо зв'язку немає, створюємо його
                INSERT INTO dbo.PhoneNumberDevices (PhoneNumberId, AppDeviceId, IsPrimary)
                VALUES (@PhoneUniqueId, @AppDeviceId, CASE WHEN EXISTS (SELECT 1 FROM dbo.PhoneNumberDevices WHERE PhoneNumberId = @PhoneUniqueId AND IsDeleted = 0) THEN 0 ELSE 1 END);
            END
            SET @Outcome = 'associated';
            SET @Message = 'Existing phone number associated with device.';
        END

        SELECT @PhoneUniqueId AS UniqueId, @Outcome AS Outcome, @Success AS Success, @Message AS Message;
    END
    ELSE
    BEGIN
        -- Номер не існує, створюємо новий
        DECLARE @OutputTable TABLE (UniqueId UNIQUEIDENTIFIER);

        INSERT INTO dbo.PhoneNumbers (PhoneNumber, Region)
        OUTPUT inserted.UniqueId INTO @OutputTable
        VALUES (@PhoneNumberString, @Region);

        SELECT @PhoneUniqueId = UniqueId FROM @OutputTable;

        SET @Outcome = 'created';
        SET @Success = 1;
        SET @Message = 'Phone number created successfully.';

        IF @AppDeviceId IS NOT NULL
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM dbo.AppDevices WHERE UniqueId = @AppDeviceId AND IsDeleted = 0)
            BEGIN
                SELECT @PhoneUniqueId AS UniqueId, 'created_but_invalid_app_device' AS Outcome, 0 AS Success, 'Phone created, but invalid AppDeviceId provided' AS Message;
                RETURN;
            END

            -- Оскільки номер новий, пристрій завжди буде першим (primary)
            INSERT INTO dbo.PhoneNumberDevices (PhoneNumberId, AppDeviceId, IsPrimary)
            VALUES (@PhoneUniqueId, @AppDeviceId, 1);

            SET @Outcome = 'created_and_associated';
            SET @Message = 'Phone number created and associated with device.';
        END

        SELECT @PhoneUniqueId AS UniqueId, @Outcome AS Outcome, @Success AS Success, @Message AS Message;
    END
END;
GO

--------------------------------------------------------------------------------
-- Процедура: VerifyPhoneForSecretKeyRecovery
-- Призначення: Перевіряє чи можна відновити секретний ключ для номера телефону.
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- Процедура: VerifyPhoneForSecretKeyRecovery
-- Призначення: Перевіряє чи можна відновити секретний ключ для номера телефону.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.VerifyPhoneForSecretKeyRecovery
    @PhoneNumberString NVARCHAR(18),
    @Region NVARCHAR(2) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @PhoneNumberId UNIQUEIDENTIFIER;
    DECLARE @HasSecureKey BIT = 0;
    DECLARE @MembershipStatus NVARCHAR(20);
    DECLARE @CreationStatus NVARCHAR(20);

    -- Знайти номер телефону
    SELECT @PhoneNumberId = UniqueId
    FROM dbo.PhoneNumbers
    WHERE PhoneNumber = @PhoneNumberString
      AND (Region = @Region OR (Region IS NULL AND @Region IS NULL))
      AND IsDeleted = 0;

    IF @PhoneNumberId IS NULL
    BEGIN
        SELECT 0 AS Success, 'Phone number not found' AS Message,
               'phone_not_found' AS Outcome, NULL AS PhoneNumberId;
        RETURN;
    END

    -- Знайти активне членство для цього номера
    SELECT TOP 1
        @MembershipStatus = Status,
        @CreationStatus = CreationStatus,
        @HasSecureKey = CASE WHEN SecureKey IS NOT NULL AND DATALENGTH(SecureKey) > 0 THEN 1 ELSE 0 END
    FROM dbo.Memberships
    WHERE PhoneNumberId = @PhoneNumberId
      AND IsDeleted = 0
    ORDER BY CreatedAt DESC;

    IF @MembershipStatus IS NULL
    BEGIN
        SELECT 0 AS Success, 'No membership found for this phone number' AS Message,
               'membership_not_found' AS Outcome, @PhoneNumberId AS PhoneNumberId;
        RETURN;
    END

    -- Перевірити, чи є секретний ключ
    IF @HasSecureKey = 0
    BEGIN
        SELECT 0 AS Success, 'No secure key found for this membership' AS Message,
               'no_secure_key' AS Outcome, @PhoneNumberId AS PhoneNumberId;
        RETURN;
    END

    -- Перевірити статус членства
    IF @MembershipStatus = 'blocked'
    BEGIN
        SELECT 0 AS Success, 'Membership is blocked' AS Message,
               'membership_blocked' AS Outcome, @PhoneNumberId AS PhoneNumberId;
        RETURN;
    END

    -- Успішна перевірка
    SELECT 1 AS Success, 'Phone number eligible for secure key recovery' AS Message,
           'eligible_for_recovery' AS Outcome, @PhoneNumberId AS PhoneNumberUniqueId;
END;
GO

-- Завершення транзакції
COMMIT TRANSACTION;
GO

-- Підтвердження
PRINT '✅ Core procedures and functions created successfully.';
GO