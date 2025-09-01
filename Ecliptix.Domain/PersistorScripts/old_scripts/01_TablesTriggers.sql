-- mssql_schema_with_enums.sql (IMPROVED)

-- Починаємо транзакцію для атомарного створення
BEGIN TRANSACTION;
GO

-- Видалення існуючих об'єктів для чистого старту
IF OBJECT_ID('dbo.TRG_PhoneNumberDevices_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_PhoneNumberDevices_Update;
IF OBJECT_ID('dbo.TRG_OtpRecords_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_OtpRecords_Update;
IF OBJECT_ID('dbo.TRG_VerificationFlows_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_VerificationFlows_Update;
IF OBJECT_ID('dbo.TRG_PhoneNumbers_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_PhoneNumbers_Update;
IF OBJECT_ID('dbo.TRG_AppDevices_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_AppDevices_Update;
IF OBJECT_ID('dbo.TRG_Memberships_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_Memberships_Update;
IF OBJECT_ID('dbo.TRG_MembershipAttempts_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_MembershipAttempts_Update;
IF OBJECT_ID('dbo.TRG_FailedOtpAttempts_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_FailedOtpAttempts_Update;
IF OBJECT_ID('dbo.TRG_LoginAttempts_Update', 'TR') IS NOT NULL DROP TRIGGER dbo.TRG_LoginAttempts_Update;
GO

IF OBJECT_ID('dbo.MembershipAttempts', 'U') IS NOT NULL DROP TABLE dbo.MembershipAttempts;
IF OBJECT_ID('dbo.LoginAttempts', 'U') IS NOT NULL DROP TABLE dbo.LoginAttempts;
IF OBJECT_ID('dbo.Memberships', 'U') IS NOT NULL DROP TABLE dbo.Memberships;
IF OBJECT_ID('dbo.FailedOtpAttempts', 'U') IS NOT NULL DROP TABLE dbo.FailedOtpAttempts;
IF OBJECT_ID('dbo.PhoneNumberDevices', 'U') IS NOT NULL DROP TABLE dbo.PhoneNumberDevices;
IF OBJECT_ID('dbo.OtpRecords', 'U') IS NOT NULL DROP TABLE dbo.OtpRecords;
IF OBJECT_ID('dbo.VerificationFlows', 'U') IS NOT NULL DROP TABLE dbo.VerificationFlows;
IF OBJECT_ID('dbo.PhoneNumbers', 'U') IS NOT NULL DROP TABLE dbo.PhoneNumbers;
IF OBJECT_ID('dbo.AppDevices', 'U') IS NOT NULL DROP TABLE dbo.AppDevices;
GO

-- Таблиця AppDevices: Зберігає інформацію про пристрої додатку
CREATE TABLE dbo.AppDevices (
    Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
    AppInstanceId   UNIQUEIDENTIFIER NOT NULL, -- Унікальний ідентифікатор екземпляра додатку
    DeviceId        UNIQUEIDENTIFIER NOT NULL, -- Унікальний ідентифікатор пристрою
    DeviceType      INT NOT NULL CONSTRAINT DF_AppDevices_DeviceType DEFAULT 1, -- Тип пристрою
    CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_AppDevices_CreatedAt DEFAULT GETUTCDATE(), -- Дата створення
    UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_AppDevices_UpdatedAt DEFAULT GETUTCDATE(), -- Дата оновлення
    IsDeleted       BIT NOT NULL CONSTRAINT DF_AppDevices_IsDeleted DEFAULT 0, -- Прапорець видалення
    UniqueId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_AppDevices_UniqueId DEFAULT NEWID(), -- Унікальний ідентифікатор запису
    CONSTRAINT UQ_AppDevices_UniqueId UNIQUE (UniqueId),
    CONSTRAINT UQ_AppDevices_DeviceId UNIQUE (DeviceId)
);
CREATE NONCLUSTERED INDEX IX_AppDevices_AppInstanceId ON dbo.AppDevices (AppInstanceId); -- Індекс для швидкого пошуку за AppInstanceId
GO

-- Таблиця PhoneNumbers: Зберігає номери телефонів
CREATE TABLE dbo.PhoneNumbers (
    Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
    PhoneNumber     NVARCHAR(18) NOT NULL, -- Номер телефону (до 18 символів для міжнародних форматів)
    Region          NVARCHAR(2), -- Код регіону (ISO 3166-1 alpha-2)
    CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_PhoneNumbers_CreatedAt DEFAULT GETUTCDATE(),
    UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_PhoneNumbers_UpdatedAt DEFAULT GETUTCDATE(),
    IsDeleted       BIT NOT NULL CONSTRAINT DF_PhoneNumbers_IsDeleted DEFAULT 0,
    UniqueId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_PhoneNumbers_UniqueId DEFAULT NEWID(),
    CONSTRAINT UQ_PhoneNumbers_UniqueId UNIQUE (UniqueId),
    CONSTRAINT UQ_PhoneNumbers_ActiveNumberRegion UNIQUE (PhoneNumber, Region, IsDeleted) -- Унікальність активних номерів у регіоні
);
CREATE NONCLUSTERED INDEX IX_PhoneNumbers_PhoneNumber_Region ON dbo.PhoneNumbers (PhoneNumber, Region); -- Індекс для швидкого пошуку
GO

-- Таблиця PhoneNumberDevices: Зв’язок між номерами телефонів і пристроями
CREATE TABLE dbo.PhoneNumberDevices (
    PhoneNumberId   UNIQUEIDENTIFIER NOT NULL, -- Посилання на PhoneNumbers.UniqueId
    AppDeviceId     UNIQUEIDENTIFIER NOT NULL, -- Посилання на AppDevices.UniqueId
    IsPrimary       BIT NOT NULL CONSTRAINT DF_PhoneNumberDevices_IsPrimary DEFAULT 0, -- Чи є основним
    CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_PhoneNumberDevices_CreatedAt DEFAULT GETUTCDATE(),
    UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_PhoneNumberDevices_UpdatedAt DEFAULT GETUTCDATE(),
    IsDeleted       BIT NOT NULL CONSTRAINT DF_PhoneNumberDevices_IsDeleted DEFAULT 0,
    CONSTRAINT PK_PhoneNumberDevices PRIMARY KEY (PhoneNumberId, AppDeviceId),
    CONSTRAINT FK_PhoneNumberDevices_PhoneNumbers FOREIGN KEY (PhoneNumberId) REFERENCES dbo.PhoneNumbers(UniqueId) ON DELETE CASCADE,
    CONSTRAINT FK_PhoneNumberDevices_AppDevices FOREIGN KEY (AppDeviceId) REFERENCES dbo.AppDevices(UniqueId) ON DELETE CASCADE
);
CREATE NONCLUSTERED INDEX IX_PhoneNumberDevices_AppDeviceId ON dbo.PhoneNumberDevices (AppDeviceId); -- Індекс для швидкого пошуку
GO

-- Таблиця VerificationFlows: Потоки верифікації
CREATE TABLE dbo.VerificationFlows (
    Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
    PhoneNumberId   BIGINT NOT NULL, -- Посилання на PhoneNumbers.Id
    AppDeviceId     UNIQUEIDENTIFIER NOT NULL, -- Посилання на AppDevices.UniqueId
    Status          NVARCHAR(20) NOT NULL
        CONSTRAINT DF_VerificationFlows_Status DEFAULT 'pending'
        CONSTRAINT CHK_VerificationFlows_Status CHECK (Status IN ('pending', 'verified', 'expired', 'failed')), -- Статус як ENUM
    Purpose         NVARCHAR(30) NOT NULL
        CONSTRAINT DF_VerificationFlows_Purpose DEFAULT 'unspecified'
        CONSTRAINT CHK_VerificationFlows_Purpose CHECK (Purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'update_phone')), -- Призначення як ENUM
    ExpiresAt       DATETIME2(7) NOT NULL, -- Дата закінчення терміну дії
    OtpCount        SMALLINT NOT NULL CONSTRAINT DF_VerificationFlows_OtpCount DEFAULT 0, -- Кількість OTP
    ConnectionId    BIGINT, -- Опціональний ідентифікатор з’єднання
    CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_VerificationFlows_CreatedAt DEFAULT GETUTCDATE(),
    UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_VerificationFlows_UpdatedAt DEFAULT GETUTCDATE(),
    IsDeleted       BIT NOT NULL CONSTRAINT DF_VerificationFlows_IsDeleted DEFAULT 0,
    UniqueId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_VerificationFlows_UniqueId DEFAULT NEWID(),
    CONSTRAINT UQ_VerificationFlows_UniqueId UNIQUE (UniqueId),
    CONSTRAINT FK_VerificationFlows_PhoneNumbers FOREIGN KEY (PhoneNumberId) REFERENCES dbo.PhoneNumbers(Id) ON DELETE CASCADE,
    CONSTRAINT FK_VerificationFlows_AppDevices FOREIGN KEY (AppDeviceId) REFERENCES dbo.AppDevices(UniqueId) ON DELETE CASCADE,
    CONSTRAINT CHK_VerificationFlows_OtpCount CHECK (OtpCount >= 0)
);
CREATE NONCLUSTERED INDEX IX_VerificationFlows_PhoneNumberId_Status ON dbo.VerificationFlows (PhoneNumberId, Status); -- Індекс для швидкого фільтрування
CREATE UNIQUE INDEX UQ_VerificationFlows_Pending ON dbo.VerificationFlows (AppDeviceId, PhoneNumberId, Purpose) WHERE (Status = 'pending' AND IsDeleted = 0); -- Унікальність активних потоків
GO

-- Таблиця OtpRecords: Записи одноразових паролів
CREATE TABLE dbo.OtpRecords (
    Id                BIGINT IDENTITY(1,1) PRIMARY KEY,
    FlowUniqueId      UNIQUEIDENTIFIER NOT NULL, -- Посилання на VerificationFlows.UniqueId
    PhoneNumberId     BIGINT NOT NULL, -- Посилання на PhoneNumbers.Id
    OtpHash           NVARCHAR(255) NOT NULL, -- Хеш OTP (обмежено для продуктивності)
    OtpSalt           NVARCHAR(255) NOT NULL, -- Сіль OTP (обмежено для продуктивності)
    ExpiresAt         DATETIME2(7) NOT NULL,
    Status            NVARCHAR(20) NOT NULL
        CONSTRAINT DF_OtpRecords_Status DEFAULT 'pending'
        CONSTRAINT CHK_OtpRecords_Status CHECK (Status IN ('pending', 'verified', 'expired', 'failed')),
    IsActive          BIT NOT NULL CONSTRAINT DF_OtpRecords_IsActive DEFAULT 1,
    CreatedAt         DATETIME2(7) NOT NULL CONSTRAINT DF_OtpRecords_CreatedAt DEFAULT GETUTCDATE(),
    UpdatedAt         DATETIME2(7) NOT NULL CONSTRAINT DF_OtpRecords_UpdatedAt DEFAULT GETUTCDATE(),
    IsDeleted         BIT NOT NULL CONSTRAINT DF_OtpRecords_IsDeleted DEFAULT 0,
    UniqueId          UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_OtpRecords_UniqueId DEFAULT NEWID(),
    CONSTRAINT UQ_OtpRecords_UniqueId UNIQUE (UniqueId),
    CONSTRAINT FK_OtpRecords_VerificationFlows FOREIGN KEY (FlowUniqueId) REFERENCES dbo.VerificationFlows(UniqueId) ON DELETE CASCADE,
    CONSTRAINT FK_OtpRecords_PhoneNumbers FOREIGN KEY (PhoneNumberId) REFERENCES dbo.PhoneNumbers(Id) ON DELETE NO ACTION
);
CREATE NONCLUSTERED INDEX IX_OtpRecords_FlowUniqueId_Status ON dbo.OtpRecords (FlowUniqueId, Status); -- Індекс для швидкого пошуку
GO

-- Таблиця FailedOtpAttempts: Невдалі спроби OTP
CREATE TABLE dbo.FailedOtpAttempts (
    Id                BIGINT IDENTITY(1,1) PRIMARY KEY,
    OtpUniqueId       UNIQUEIDENTIFIER NOT NULL, -- Посилання на OtpRecords.UniqueId
    FlowUniqueId      UNIQUEIDENTIFIER NOT NULL, -- Посилання на VerificationFlows.UniqueId
    AttemptTime       DATETIME2(7) NOT NULL CONSTRAINT DF_FailedOtpAttempts_AttemptTime DEFAULT GETUTCDATE(),
    CreatedAt         DATETIME2(7) NOT NULL CONSTRAINT DF_FailedOtpAttempts_CreatedAt DEFAULT GETUTCDATE(),
    UpdatedAt         DATETIME2(7) NOT NULL CONSTRAINT DF_FailedOtpAttempts_UpdatedAt DEFAULT GETUTCDATE(),
    IsDeleted         BIT NOT NULL CONSTRAINT DF_FailedOtpAttempts_IsDeleted DEFAULT 0,
    CONSTRAINT FK_FailedOtpAttempts_OtpRecords FOREIGN KEY (OtpUniqueId) REFERENCES dbo.OtpRecords(UniqueId) ON DELETE CASCADE,
    CONSTRAINT FK_FailedOtpAttempts_VerificationFlows FOREIGN KEY (FlowUniqueId) REFERENCES dbo.VerificationFlows(UniqueId) ON DELETE NO ACTION
);
CREATE NONCLUSTERED INDEX IX_FailedOtpAttempts_OtpUniqueId ON dbo.FailedOtpAttempts (OtpUniqueId); -- Індекс для швидкого пошуку
GO

-- Таблиця Memberships: Членства користувачів
CREATE TABLE dbo.Memberships (
    Id                      BIGINT IDENTITY(1,1) PRIMARY KEY,
    PhoneNumberId           UNIQUEIDENTIFIER NOT NULL, -- Посилання на PhoneNumbers.UniqueId
    AppDeviceId             UNIQUEIDENTIFIER NOT NULL, -- Посилання на AppDevices.UniqueId
    VerificationFlowId      UNIQUEIDENTIFIER NOT NULL, -- Посилання на VerificationFlows.UniqueId
    SecureKey               VARBINARY(MAX), -- Зашифрований ключ
    Status                  NVARCHAR(20) NOT NULL
        CONSTRAINT DF_Memberships_Status DEFAULT 'inactive'
        CONSTRAINT CHK_Memberships_Status CHECK (Status IN ('active', 'inactive')),
    CreationStatus          NVARCHAR(20)
        CONSTRAINT CHK_Memberships_CreationStatus CHECK (CreationStatus IN ('otp_verified', 'secure_key_set', 'passphrase_set')),
    CreatedAt               DATETIME2(7) NOT NULL CONSTRAINT DF_Memberships_CreatedAt DEFAULT GETUTCDATE(),
    UpdatedAt               DATETIME2(7) NOT NULL CONSTRAINT DF_Memberships_UpdatedAt DEFAULT GETUTCDATE(),
    IsDeleted               BIT NOT NULL CONSTRAINT DF_Memberships_IsDeleted DEFAULT 0,
    UniqueId                UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_Memberships_UniqueId DEFAULT NEWID(),
    CONSTRAINT UQ_Memberships_UniqueId UNIQUE (UniqueId),
    CONSTRAINT FK_Memberships_PhoneNumbers FOREIGN KEY (PhoneNumberId) REFERENCES dbo.PhoneNumbers(UniqueId) ON DELETE NO ACTION,
    CONSTRAINT FK_Memberships_AppDevices FOREIGN KEY (AppDeviceId) REFERENCES dbo.AppDevices(UniqueId) ON DELETE NO ACTION,
    CONSTRAINT FK_Memberships_VerificationFlows FOREIGN KEY (VerificationFlowId) REFERENCES dbo.VerificationFlows(UniqueId) ON DELETE NO ACTION,
    CONSTRAINT UQ_Memberships_ActiveMembership UNIQUE (PhoneNumberId, AppDeviceId, IsDeleted)
);
CREATE NONCLUSTERED INDEX IX_Memberships_PhoneNumberId_Status ON dbo.Memberships (PhoneNumberId, Status); -- Індекс для швидкого фільтрування
GO

-- Таблиця LoginAttempts: Спроби входу
CREATE TABLE dbo.LoginAttempts (
    Id           BIGINT IDENTITY(1,1) PRIMARY KEY,
    Timestamp    DATETIME2(7) NOT NULL CONSTRAINT DF_LoginAttempts_Timestamp DEFAULT GETUTCDATE(),
    PhoneNumber  NVARCHAR(18) NOT NULL, -- Номер телефону для входу
    Outcome      NVARCHAR(255) NOT NULL, -- Результат спроби (обмежено для продуктивності)
    IsSuccess    BIT NOT NULL CONSTRAINT DF_LoginAttempts_IsSuccess DEFAULT 0,
    CreatedAt    DATETIME2(7) NOT NULL CONSTRAINT DF_LoginAttempts_CreatedAt DEFAULT GETUTCDATE(),
    UpdatedAt    DATETIME2(7) NOT NULL CONSTRAINT DF_LoginAttempts_UpdatedAt DEFAULT GETUTCDATE()
);
CREATE NONCLUSTERED INDEX IX_LoginAttempts_PhoneNumber_Timestamp ON dbo.LoginAttempts (PhoneNumber, Timestamp); -- Індекс для швидкого аналізу
GO

-- Таблиця MembershipAttempts: Спроби створення членства
CREATE TABLE dbo.MembershipAttempts (
    Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
    PhoneNumberId   UNIQUEIDENTIFIER NOT NULL, -- Посилання на PhoneNumbers.UniqueId
    Timestamp       DATETIME2(7) NOT NULL CONSTRAINT DF_MembershipAttempts_Timestamp DEFAULT GETUTCDATE(),
    Outcome         NVARCHAR(255) NOT NULL, -- Результат спроби (обмежено для продуктивності)
    IsSuccess       BIT NOT NULL CONSTRAINT DF_MembershipAttempts_IsSuccess DEFAULT 0,
    CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_MembershipAttempts_CreatedAt DEFAULT GETUTCDATE(),
    UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_MembershipAttempts_UpdatedAt DEFAULT GETUTCDATE(),
    IsDeleted       BIT NOT NULL CONSTRAINT DF_MembershipAttempts_IsDeleted DEFAULT 0,
    CONSTRAINT FK_MembershipAttempts_PhoneNumbers FOREIGN KEY (PhoneNumberId) REFERENCES dbo.PhoneNumbers(UniqueId) ON DELETE CASCADE
);
CREATE NONCLUSTERED INDEX IX_MembershipAttempts_PhoneNumberId_Timestamp ON dbo.MembershipAttempts (PhoneNumberId, Timestamp); -- Індекс для швидкого аналізу
GO

IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'EventLog')
BEGIN
    CREATE TABLE dbo.EventLog (
        Id BIGINT IDENTITY(1,1) PRIMARY KEY,
        EventType NVARCHAR(50) NOT NULL,
        Message NVARCHAR(MAX) NOT NULL,
        CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE()
    );
END
GO

-- Тригери для автоматичного оновлення UpdatedAt (оптимізовані для уникнення рекурсії)
CREATE TRIGGER TRG_AppDevices_Update ON dbo.AppDevices FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN; -- Уникаємо рекурсії
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.AppDevices t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
GO

CREATE TRIGGER TRG_PhoneNumbers_Update ON dbo.PhoneNumbers FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.PhoneNumbers t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
GO

CREATE TRIGGER TRG_PhoneNumberDevices_Update ON dbo.PhoneNumberDevices FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.PhoneNumberDevices t
    INNER JOIN inserted i ON t.PhoneNumberId = i.PhoneNumberId AND t.AppDeviceId = i.AppDeviceId;
END;
GO

CREATE TRIGGER TRG_VerificationFlows_Update ON dbo.VerificationFlows FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.VerificationFlows t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
GO

CREATE TRIGGER TRG_OtpRecords_Update ON dbo.OtpRecords FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.OtpRecords t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
GO

CREATE TRIGGER TRG_FailedOtpAttempts_Update ON dbo.FailedOtpAttempts FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.FailedOtpAttempts t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
GO

CREATE TRIGGER TRG_Memberships_Update ON dbo.Memberships FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.Memberships t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
GO

CREATE TRIGGER TRG_MembershipAttempts_Update ON dbo.MembershipAttempts FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.MembershipAttempts t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
GO

CREATE TRIGGER TRG_LoginAttempts_Update ON dbo.LoginAttempts FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
    UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.LoginAttempts t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
GO

-- Завершення транзакції
COMMIT TRANSACTION;
GO

-- Підтвердження створення
PRINT '✅ Tables with ENUM-like constraints, triggers, and indexes created successfully (IMPROVED).';
GO