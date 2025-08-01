create table AppDevices
(
    Id            bigint identity
        primary key,
    AppInstanceId uniqueidentifier                              not null,
    DeviceId      uniqueidentifier                              not null
        constraint UQ_AppDevices_DeviceId
            unique,
    DeviceType    int
        constraint DF_AppDevices_DeviceType default 1           not null,
    CreatedAt     datetime2
        constraint DF_AppDevices_CreatedAt default getutcdate() not null,
    UpdatedAt     datetime2
        constraint DF_AppDevices_UpdatedAt default getutcdate() not null,
    IsDeleted     bit
        constraint DF_AppDevices_IsDeleted default 0            not null,
    UniqueId      uniqueidentifier
        constraint DF_AppDevices_UniqueId default newid()       not null
        constraint UQ_AppDevices_UniqueId
            unique
)
    go

create index IX_AppDevices_AppInstanceId
    on AppDevices (AppInstanceId)
    go

-- Тригери для автоматичного оновлення UpdatedAt (оптимізовані для уникнення рекурсії)
CREATE TRIGGER TRG_AppDevices_Update ON dbo.AppDevices FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN; -- Уникаємо рекурсії
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.AppDevices t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
go

create table EventLog
(
    Id        bigint identity
        primary key,
    EventType nvarchar(50)                   not null,
    Message   nvarchar(max)                  not null,
    CreatedAt datetime2 default getutcdate() not null
)
    go

create table LoginAttempts
(
    Id          bigint identity
        primary key,
    Timestamp   datetime2
        constraint DF_LoginAttempts_Timestamp default getutcdate() not null,
    PhoneNumber nvarchar(18)                                       not null,
    Outcome     nvarchar(255)                                      not null,
    IsSuccess   bit
        constraint DF_LoginAttempts_IsSuccess default 0            not null,
    CreatedAt   datetime2
        constraint DF_LoginAttempts_CreatedAt default getutcdate() not null,
    UpdatedAt   datetime2
        constraint DF_LoginAttempts_UpdatedAt default getutcdate() not null
)
    go

create index IX_LoginAttempts_PhoneNumber_Timestamp
    on LoginAttempts (PhoneNumber, Timestamp)
    go

CREATE TRIGGER TRG_LoginAttempts_Update ON dbo.LoginAttempts FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.LoginAttempts t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
go

create table Metadata
(
    PersistenceId nvarchar(255) not null,
    SequenceNr    bigint        not null,
    constraint PK_Metadata
        primary key (PersistenceId, SequenceNr)
)
    go

create table PhoneNumbers
(
    Id          bigint identity
        primary key,
    PhoneNumber nvarchar(18)                                      not null,
    Region      nvarchar(2),
    CreatedAt   datetime2
        constraint DF_PhoneNumbers_CreatedAt default getutcdate() not null,
    UpdatedAt   datetime2
        constraint DF_PhoneNumbers_UpdatedAt default getutcdate() not null,
    IsDeleted   bit
        constraint DF_PhoneNumbers_IsDeleted default 0            not null,
    UniqueId    uniqueidentifier
        constraint DF_PhoneNumbers_UniqueId default newid()       not null
        constraint UQ_PhoneNumbers_UniqueId
            unique,
    constraint UQ_PhoneNumbers_ActiveNumberRegion
        unique (PhoneNumber, Region, IsDeleted)
)
    go

create table MembershipAttempts
(
    Id            bigint identity
        primary key,
    PhoneNumberId uniqueidentifier                                      not null
        constraint FK_MembershipAttempts_PhoneNumbers
            references PhoneNumbers (UniqueId)
            on delete cascade,
    Timestamp     datetime2
        constraint DF_MembershipAttempts_Timestamp default getutcdate() not null,
    Outcome       nvarchar(255)                                         not null,
    IsSuccess     bit
        constraint DF_MembershipAttempts_IsSuccess default 0            not null,
    CreatedAt     datetime2
        constraint DF_MembershipAttempts_CreatedAt default getutcdate() not null,
    UpdatedAt     datetime2
        constraint DF_MembershipAttempts_UpdatedAt default getutcdate() not null,
    IsDeleted     bit
        constraint DF_MembershipAttempts_IsDeleted default 0            not null
)
    go

create index IX_MembershipAttempts_PhoneNumberId_Timestamp
    on MembershipAttempts (PhoneNumberId, Timestamp)
    go

CREATE TRIGGER TRG_MembershipAttempts_Update ON dbo.MembershipAttempts FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.MembershipAttempts t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
go

create table PhoneNumberDevices
(
    PhoneNumberId uniqueidentifier                                      not null
        constraint FK_PhoneNumberDevices_PhoneNumbers
            references PhoneNumbers (UniqueId)
            on delete cascade,
    AppDeviceId   uniqueidentifier                                      not null
        constraint FK_PhoneNumberDevices_AppDevices
            references AppDevices (UniqueId)
            on delete cascade,
    IsPrimary     bit
        constraint DF_PhoneNumberDevices_IsPrimary default 0            not null,
    CreatedAt     datetime2
        constraint DF_PhoneNumberDevices_CreatedAt default getutcdate() not null,
    UpdatedAt     datetime2
        constraint DF_PhoneNumberDevices_UpdatedAt default getutcdate() not null,
    IsDeleted     bit
        constraint DF_PhoneNumberDevices_IsDeleted default 0            not null,
    constraint PK_PhoneNumberDevices
        primary key (PhoneNumberId, AppDeviceId)
)
    go

create index IX_PhoneNumberDevices_AppDeviceId
    on PhoneNumberDevices (AppDeviceId)
    go

CREATE TRIGGER TRG_PhoneNumberDevices_Update ON dbo.PhoneNumberDevices FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.PhoneNumberDevices t
    INNER JOIN inserted i ON t.PhoneNumberId = i.PhoneNumberId AND t.AppDeviceId = i.AppDeviceId;
END;
go

create index IX_PhoneNumbers_PhoneNumber_Region
    on PhoneNumbers (PhoneNumber, Region)
    go

CREATE TRIGGER TRG_PhoneNumbers_Update ON dbo.PhoneNumbers FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.PhoneNumbers t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
go

create table VerificationFlows
(
    Id            bigint identity
        primary key,
    PhoneNumberId bigint                                               not null
        constraint FK_VerificationFlows_PhoneNumbers
            references PhoneNumbers
            on delete cascade,
    AppDeviceId   uniqueidentifier                                     not null
        constraint FK_VerificationFlows_AppDevices
            references AppDevices (UniqueId)
            on delete cascade,
    Status        nvarchar(20)
        constraint DF_VerificationFlows_Status default 'pending'       not null
        constraint CHK_VerificationFlows_Status
            check ([Status] = 'failed' OR [Status] = 'expired' OR [Status] = 'verified' OR [Status] = 'pending'),
    Purpose       nvarchar(30)
        constraint DF_VerificationFlows_Purpose default 'unspecified'  not null
        constraint CHK_VerificationFlows_Purpose
            check ([Purpose] = 'update_phone' OR [Purpose] = 'password_recovery' OR [Purpose] = 'login' OR
                   [Purpose] = 'registration' OR [Purpose] = 'unspecified'),
    ExpiresAt     datetime2                                            not null,
    OtpCount      smallint
        constraint DF_VerificationFlows_OtpCount default 0             not null
        constraint CHK_VerificationFlows_OtpCount
            check ([OtpCount] >= 0),
    ConnectionId  bigint,
    CreatedAt     datetime2
        constraint DF_VerificationFlows_CreatedAt default getutcdate() not null,
    UpdatedAt     datetime2
        constraint DF_VerificationFlows_UpdatedAt default getutcdate() not null,
    IsDeleted     bit
        constraint DF_VerificationFlows_IsDeleted default 0            not null,
    UniqueId      uniqueidentifier
        constraint DF_VerificationFlows_UniqueId default newid()       not null
        constraint UQ_VerificationFlows_UniqueId
            unique
)
    go

create table Memberships
(
    Id                 bigint identity
        primary key,
    PhoneNumberId      uniqueidentifier                          not null
        constraint FK_Memberships_PhoneNumbers
            references PhoneNumbers (UniqueId),
    AppDeviceId        uniqueidentifier                          not null
        constraint FK_Memberships_AppDevices
            references AppDevices (UniqueId),
    VerificationFlowId uniqueidentifier                          not null
        constraint FK_Memberships_VerificationFlows
            references VerificationFlows (UniqueId),
    SecureKey          varbinary(max),
    Status             nvarchar(20)
        constraint DF_Memberships_Status default 'inactive'      not null
        constraint CHK_Memberships_Status
            check ([Status] = 'inactive' OR [Status] = 'active'),
    CreationStatus     nvarchar(20)
        constraint CHK_Memberships_CreationStatus
            check ([CreationStatus] = 'passphrase_set' OR [CreationStatus] = 'secure_key_set' OR
                   [CreationStatus] = 'otp_verified'),
    CreatedAt          datetime2
        constraint DF_Memberships_CreatedAt default getutcdate() not null,
    UpdatedAt          datetime2
        constraint DF_Memberships_UpdatedAt default getutcdate() not null,
    IsDeleted          bit
        constraint DF_Memberships_IsDeleted default 0            not null,
    UniqueId           uniqueidentifier
        constraint DF_Memberships_UniqueId default newid()       not null
        constraint UQ_Memberships_UniqueId
            unique,
    constraint UQ_Memberships_ActiveMembership
        unique (PhoneNumberId, AppDeviceId, IsDeleted)
)
    go

create index IX_Memberships_PhoneNumberId_Status
    on Memberships (PhoneNumberId, Status)
    go

CREATE TRIGGER TRG_Memberships_Update ON dbo.Memberships FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.Memberships t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
go

create table OtpRecords
(
    Id            bigint identity
        primary key,
    FlowUniqueId  uniqueidentifier                              not null
        constraint FK_OtpRecords_VerificationFlows
            references VerificationFlows (UniqueId)
            on delete cascade,
    PhoneNumberId bigint                                        not null
        constraint FK_OtpRecords_PhoneNumbers
            references PhoneNumbers,
    OtpHash       nvarchar(255)                                 not null,
    OtpSalt       nvarchar(255)                                 not null,
    ExpiresAt     datetime2                                     not null,
    Status        nvarchar(20)
        constraint DF_OtpRecords_Status default 'pending'       not null
        constraint CHK_OtpRecords_Status
            check ([Status] = 'failed' OR [Status] = 'expired' OR [Status] = 'verified' OR [Status] = 'pending'),
    IsActive      bit
        constraint DF_OtpRecords_IsActive default 1             not null,
    CreatedAt     datetime2
        constraint DF_OtpRecords_CreatedAt default getutcdate() not null,
    UpdatedAt     datetime2
        constraint DF_OtpRecords_UpdatedAt default getutcdate() not null,
    IsDeleted     bit
        constraint DF_OtpRecords_IsDeleted default 0            not null,
    UniqueId      uniqueidentifier
        constraint DF_OtpRecords_UniqueId default newid()       not null
        constraint UQ_OtpRecords_UniqueId
            unique
)
    go

create table FailedOtpAttempts
(
    Id           bigint identity
        primary key,
    OtpUniqueId  uniqueidentifier                                        not null
        constraint FK_FailedOtpAttempts_OtpRecords
            references OtpRecords (UniqueId)
            on delete cascade,
    FlowUniqueId uniqueidentifier                                        not null
        constraint FK_FailedOtpAttempts_VerificationFlows
            references VerificationFlows (UniqueId),
    AttemptTime  datetime2
        constraint DF_FailedOtpAttempts_AttemptTime default getutcdate() not null,
    CreatedAt    datetime2
        constraint DF_FailedOtpAttempts_CreatedAt default getutcdate()   not null,
    UpdatedAt    datetime2
        constraint DF_FailedOtpAttempts_UpdatedAt default getutcdate()   not null,
    IsDeleted    bit
        constraint DF_FailedOtpAttempts_IsDeleted default 0              not null
)
    go

create index IX_FailedOtpAttempts_OtpUniqueId
    on FailedOtpAttempts (OtpUniqueId)
    go

CREATE TRIGGER TRG_FailedOtpAttempts_Update ON dbo.FailedOtpAttempts FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.FailedOtpAttempts t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
go

create index IX_OtpRecords_FlowUniqueId_Status
    on OtpRecords (FlowUniqueId, Status)
    go

CREATE TRIGGER TRG_OtpRecords_Update ON dbo.OtpRecords FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.OtpRecords t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
go

create index IX_VerificationFlows_PhoneNumberId_Status
    on VerificationFlows (PhoneNumberId, Status)
    go

create unique index UQ_VerificationFlows_Pending
    on VerificationFlows (AppDeviceId, PhoneNumberId, Purpose)
    where [Status] = 'pending' AND [IsDeleted] = 0
go

CREATE TRIGGER TRG_VerificationFlows_Update ON dbo.VerificationFlows FOR UPDATE AS
BEGIN
    SET NOCOUNT ON;
    IF UPDATE(UpdatedAt) RETURN;
UPDATE t SET UpdatedAt = GETUTCDATE()
    FROM dbo.VerificationFlows t
    INNER JOIN inserted i ON t.Id = i.Id;
END;
go

create table journal
(
    ordering        bigint identity
        constraint PK_journal
            primary key,
    created         bigint         not null,
    deleted         bit            not null,
    persistence_id  nvarchar(255)  not null,
    sequence_number bigint         not null,
    message         varbinary(max) not null,
    manifest        nvarchar(500),
    identifier      int,
    writer_uuid     nvarchar(128),
    constraint UQ_journal
        unique (persistence_id, sequence_number)
)
    go

create index IX_journal_sequence_number
    on journal (sequence_number)
    go

create index IX_journal_created
    on journal (created)
    go

create table snapshot
(
    persistence_id  nvarchar(255) not null,
    sequence_number bigint        not null,
    created         datetime2     not null,
    snapshot        varbinary(max),
    manifest        nvarchar(500),
    serializer_id   int,
    constraint PK_snapshot
        primary key (persistence_id, sequence_number)
)
    go

create index IX_snapshot_sequence_number
    on snapshot (sequence_number)
    go

create index IX_snapshot_created
    on snapshot (created)
    go

create table tags
(
    ordering_id    bigint       not null,
    tag            nvarchar(64) not null,
    sequence_nr    bigint       not null,
    persistence_id varchar(255) not null,
    primary key (ordering_id, tag, persistence_id)
)
    go

create index IX_tags_persistence_id_sequence_nr
    on tags (persistence_id, sequence_nr)
    go

create index IX_tags_tag
    on tags (tag)
    go

--------------------------------------------------------------------------------
-- Процедура: CreateMembership
-- Призначення: Створює нове членство з обмеженням спроб.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.CreateMembership
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
  AND Timestamp > DATEADD(hour, -@AttemptWindowHours, GETUTCDATE());

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
go

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
go

--------------------------------------------------------------------------------
-- FN: GetFullFlowState
-- Призначення: Повертає повний стан потоку з активним OTP.
-- Використовується як єдина точка для отримання даних потоку.
--------------------------------------------------------------------------------
CREATE FUNCTION dbo.GetFullFlowState(@FlowUniqueId UNIQUEIDENTIFIER)
    RETURNS TABLE
    AS RETURN
(
    SELECT
        vf.UniqueId         AS UniqueIdentifier,
        pn.UniqueId         AS PhoneNumberIdentifier,
        vf.AppDeviceId      AS AppDeviceIdentifier,
        vf.ConnectionId     AS ConnectId,
        vf.ExpiresAt,
        vf.Status,
        vf.Purpose,
        vf.OtpCount,
        o.UniqueId          AS Otp_UniqueIdentifier,
        o.FlowUniqueId      AS Otp_FlowUniqueId,
        o.OtpHash           AS Otp_OtpHash,
        o.OtpSalt           AS Otp_OtpSalt,
        o.ExpiresAt         AS Otp_ExpiresAt,
        o.Status            AS Otp_Status,
        o.IsActive          AS Otp_IsActive
    FROM dbo.VerificationFlows AS vf
    JOIN dbo.PhoneNumbers AS pn ON vf.PhoneNumberId = pn.Id
    LEFT JOIN dbo.OtpRecords AS o ON o.FlowUniqueId = vf.UniqueId AND o.IsActive = 1 AND o.IsDeleted = 0 AND o.ExpiresAt > GETUTCDATE()
    WHERE vf.UniqueId = @FlowUniqueId
)
go

--------------------------------------------------------------------------------
-- FN: GetPhoneNumber
-- Призначення: Отримує деталі номеру телефону за його ID.
--------------------------------------------------------------------------------
CREATE FUNCTION dbo.GetPhoneNumber (@PhoneUniqueId UNIQUEIDENTIFIER)
    RETURNS TABLE AS RETURN
( SELECT pn.PhoneNumber, pn.Region, pn.UniqueId FROM dbo.PhoneNumbers AS pn WHERE pn.UniqueId = @PhoneUniqueId AND pn.IsDeleted = 0 )
go

--------------------------------------------------------------------------------
-- SP: InitiateVerificationFlow
-- Призначення: Атомарно отримує існуючий активний потік АБО створює новий.
-- Це єдина точка входу для початку верифікації.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.InitiateVerificationFlow
    @AppDeviceId UNIQUEIDENTIFIER,
    @PhoneUniqueId UNIQUEIDENTIFIER,
    @Purpose NVARCHAR(30),
    @ConnectionId BIGINT = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    -- 1. Валідація
    DECLARE @PhoneNumberId BIGINT;
SELECT @PhoneNumberId = Id FROM dbo.PhoneNumbers WHERE UniqueId = @PhoneUniqueId AND IsDeleted = 0;
IF @PhoneNumberId IS NULL
BEGIN
SELECT 'phone_not_found' AS Outcome;
RETURN;
END

    -- 2. Перевірка наявності існуючого верифікованого дійсного флоу
    DECLARE @ExistingVerifiedFlowId UNIQUEIDENTIFIER;
SELECT TOP 1 @ExistingVerifiedFlowId = UniqueId
FROM dbo.VerificationFlows
WHERE PhoneNumberId = @PhoneNumberId
  AND Status = 'verified'
  AND IsDeleted = 0
  AND ExpiresAt > GETUTCDATE()
ORDER BY CreatedAt DESC;

IF @ExistingVerifiedFlowId IS NOT NULL
BEGIN
SELECT *, 'verified' AS Outcome FROM dbo.GetFullFlowState(@ExistingVerifiedFlowId);
RETURN;
END

    -- 3. Глобальний Rate Limiting
    DECLARE @MaxFlowsPerHour INT = 5;
    IF (SELECT COUNT(*) FROM dbo.VerificationFlows WHERE PhoneNumberId = @PhoneNumberId AND CreatedAt > DATEADD(hour, -1, GETUTCDATE())) >= @MaxFlowsPerHour
BEGIN
SELECT 'global_rate_limit_exceeded' AS Outcome;
RETURN;
END

    -- 4. Спочатку деактивуємо всі старі прострочені потоки для цієї пари, щоб звільнити унікальний індекс
UPDATE dbo.VerificationFlows
SET Status = 'expired'
WHERE AppDeviceId = @AppDeviceId AND PhoneNumberId = @PhoneNumberId AND Purpose = @Purpose AND Status = 'pending' AND IsDeleted = 0 AND ExpiresAt <= GETUTCDATE();

-- 5. Атомарна спроба "INSERT, CATCH, SELECT"
DECLARE @NewFlowUniqueId UNIQUEIDENTIFIER = NEWID();
    DECLARE @ExpiresAt DATETIME2(7) = DATEADD(minute, 5, GETUTCDATE());

BEGIN TRY
INSERT INTO dbo.VerificationFlows (UniqueId, AppDeviceId, PhoneNumberId, Purpose, ExpiresAt, ConnectionId, OtpCount)
        VALUES (@NewFlowUniqueId, @AppDeviceId, @PhoneNumberId, @Purpose, @ExpiresAt, @ConnectionId, 0);

SELECT *, 'created' AS Outcome FROM dbo.GetFullFlowState(@NewFlowUniqueId);
END TRY
BEGIN CATCH
IF ERROR_NUMBER() IN (2601, 2627) -- Порушення унікальності
BEGIN
            -- Race condition: інший потік нас випередив. Безпечно отримуємо існуючий запис.
            DECLARE @ExistingFlowId UNIQUEIDENTIFIER;
SELECT TOP 1 @ExistingFlowId = UniqueId
FROM dbo.VerificationFlows
WHERE AppDeviceId = @AppDeviceId AND PhoneNumberId = @PhoneNumberId AND Purpose = @Purpose AND Status = 'pending' AND IsDeleted = 0 AND ExpiresAt > GETUTCDATE()
ORDER BY CreatedAt DESC;

IF @ExistingFlowId IS NOT NULL
SELECT *, 'retrieved' AS Outcome FROM dbo.GetFullFlowState(@ExistingFlowId);
ELSE
SELECT 'conflict_unresolved' AS Outcome;
END
ELSE
            THROW;
END CATCH;
END;
go

--------------------------------------------------------------------------------
-- SP: InsertOtpRecord
-- Призначення: Створює новий OTP, збільшуючи лічильник. Містить захист від перевищення ліміту.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.InsertOtpRecord
    @FlowUniqueId UNIQUEIDENTIFIER, @OtpHash NVARCHAR(MAX), @OtpSalt NVARCHAR(MAX), @ExpiresAt DATETIME2(7), @Status NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @FlowId BIGINT, @PhoneNumberId BIGINT, @OtpCount SMALLINT;

SELECT @FlowId = Id, @PhoneNumberId = PhoneNumberId, @OtpCount = OtpCount
FROM dbo.VerificationFlows
WHERE UniqueId = @FlowUniqueId AND Status = 'pending' AND IsDeleted = 0 AND ExpiresAt > GETUTCDATE();

IF @FlowId IS NULL
BEGIN
SELECT CAST(NULL AS UNIQUEIDENTIFIER) AS OtpUniqueId, 'flow_not_found_or_invalid' AS Outcome; RETURN;
END

    -- Захист від перевищення ліміту спроб на рівні вставки
    IF @OtpCount >= 5
BEGIN
UPDATE dbo.VerificationFlows SET Status = 'failed' WHERE Id = @FlowId;
SELECT CAST(NULL AS UNIQUEIDENTIFIER) AS OtpUniqueId, 'max_otp_attempts_reached' AS Outcome; RETURN;
END

    DECLARE @OtpOutputTable TABLE (UniqueId UNIQUEIDENTIFIER);
INSERT INTO dbo.OtpRecords (FlowUniqueId, PhoneNumberId, OtpHash, OtpSalt, ExpiresAt, Status, IsActive)
    OUTPUT inserted.UniqueId INTO @OtpOutputTable(UniqueId)
VALUES (@FlowUniqueId, @PhoneNumberId, @OtpHash, @OtpSalt, @ExpiresAt, @Status, 1);

UPDATE dbo.VerificationFlows SET OtpCount = OtpCount + 1 WHERE Id = @FlowId;
SELECT UniqueId AS OtpUniqueId, 'created' AS Outcome FROM @OtpOutputTable;
END;
go

--------------------------------------------------------------------------------
-- 1. Допоміжна внутрішня процедура для отримання повного стану потоку
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.Internal_GetFullFlowState
    @FlowUniqueId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;
SELECT
    vf.UniqueId         AS UniqueIdentifier,
    pn.UniqueId         AS PhoneNumberIdentifier,
    vf.AppDeviceId      AS AppDeviceIdentifier,
    vf.ConnectionId     AS ConnectId,
    vf.ExpiresAt,
    vf.Status,
    vf.Purpose,
    vf.OtpCount,
    o.UniqueId          AS Otp_UniqueIdentifier,
    o.FlowUniqueId      AS Otp_FlowUniqueId,
    o.OtpHash           AS Otp_OtpHash,
    o.OtpSalt           AS Otp_OtpSalt,
    o.ExpiresAt         AS Otp_ExpiresAt,
    o.Status            AS Otp_Status,
    o.IsActive          AS Otp_IsActive
FROM dbo.VerificationFlows AS vf
         JOIN dbo.PhoneNumbers AS pn ON vf.PhoneNumberId = pn.Id
         LEFT JOIN dbo.OtpRecords AS o ON o.FlowUniqueId = vf.UniqueId AND o.IsActive = 1 AND o.IsDeleted = 0 AND o.ExpiresAt > GETUTCDATE()
WHERE vf.UniqueId = @FlowUniqueId;
END;
go

--------------------------------------------------------------------------------
-- Процедура: LogLoginAttempt
-- Призначення: Логує спробу входу.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.LogLoginAttempt
    @PhoneNumber NVARCHAR(18),
    @Outcome NVARCHAR(MAX),
    @IsSuccess BIT
AS
BEGIN
    SET NOCOUNT ON;
INSERT INTO dbo.LoginAttempts (Timestamp, PhoneNumber, Outcome, IsSuccess)
VALUES (GETUTCDATE(), @PhoneNumber, @Outcome, @IsSuccess);
END;
go

--------------------------------------------------------------------------------
-- Процедура: LogMembershipAttempt
-- Призначення: Логує спробу створення членства.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.LogMembershipAttempt
    @PhoneNumberId UNIQUEIDENTIFIER,
    @Outcome NVARCHAR(MAX),
    @IsSuccess BIT
AS
BEGIN
    SET NOCOUNT ON;
INSERT INTO dbo.MembershipAttempts (PhoneNumberId, Timestamp, Outcome, IsSuccess)
VALUES (@PhoneNumberId, GETUTCDATE(), @Outcome, @IsSuccess);
END;
go

--------------------------------------------------------------------------------
-- Procedure: LoginMembership
-- Purpose: Authenticates a user with lockout logic and returns SecureKey.
--------------------------------------------------------------------------------
CREATE   PROCEDURE dbo.LoginMembership
    @PhoneNumber NVARCHAR(18)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @MembershipUniqueId UNIQUEIDENTIFIER, @Status NVARCHAR(20), @Outcome NVARCHAR(100);
    DECLARE @PhoneNumberId UNIQUEIDENTIFIER, @StoredSecureKey VARBINARY(MAX), @CreationStatus NVARCHAR(20);
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
    DECLARE @FailedAttemptsCount INT;
    DECLARE @LockoutDurationMinutes INT = 5;
    DECLARE @MaxAttemptsBeforeLockout INT = 5;
    DECLARE @LockoutMarkerPrefix NVARCHAR(20) = 'LOCKED_UNTIL:';
    DECLARE @LockedUntilTs DATETIME2(7);
    DECLARE @LastLockoutInitTime DATETIME2(7);
    DECLARE @LockoutMarkerOutcome NVARCHAR(MAX);
    DECLARE @LockoutPattern NVARCHAR(30) = @LockoutMarkerPrefix + '%';

    -- 1. Check for active lockout
SELECT TOP 1 @LockoutMarkerOutcome = Outcome, @LastLockoutInitTime = Timestamp
FROM dbo.LoginAttempts
WHERE PhoneNumber = @PhoneNumber AND Outcome LIKE @LockoutPattern
ORDER BY Timestamp DESC;

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
  AND Timestamp <= @LastLockoutInitTime
  AND (IsSuccess = 0 OR Outcome LIKE @LockoutPattern);
END
END

    -- 2. Count relevant failed attempts
SELECT @FailedAttemptsCount = COUNT(*)
FROM dbo.LoginAttempts
WHERE PhoneNumber = @PhoneNumber
  AND IsSuccess = 0
  AND Timestamp > ISNULL((SELECT MAX(Timestamp) FROM dbo.LoginAttempts WHERE PhoneNumber = @PhoneNumber AND Outcome LIKE @LockoutPattern), '1900-01-01');

-- 3. Login attempt logic
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

    -- 4. Handle result
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
        SET @FailedAttemptsCount = @FailedAttemptsCount + 1;
        IF @FailedAttemptsCount >= @MaxAttemptsBeforeLockout
BEGIN
            SET @LockedUntilTs = DATEADD(minute, @LockoutDurationMinutes, @CurrentTime);
            DECLARE @NewLockoutMarker NVARCHAR(MAX) = CONCAT(@LockoutMarkerPrefix, CONVERT(NVARCHAR(30), @LockedUntilTs, 127));
EXEC dbo.LogLoginAttempt @PhoneNumber, @NewLockoutMarker, 0;
            SET @Outcome = CAST(@LockoutDurationMinutes AS NVARCHAR(100));
END
SELECT NULL AS MembershipUniqueId,
       NULL AS Status,
       @Outcome AS Outcome,
       NULL AS SecureKey;
END
END;
go

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
go

--------------------------------------------------------------------------------
-- SP: RequestResendOtp
-- Призначення: Перевіряє всі бізнес-правила для повторної відправки OTP.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.RequestResendOtp
    @FlowUniqueId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Outcome NVARCHAR(50);
    DECLARE @MaxOtpAttempts INT = 5;
    DECLARE @MinResendIntervalSeconds INT = 30;
    DECLARE @OtpCount SMALLINT;
    DECLARE @SessionExpiresAt DATETIME2(7);
    DECLARE @LastOtpTimestamp DATETIME2(7);
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

    -- Крок 1: Отримуємо дані про потік верифікації
SELECT
    @OtpCount = OtpCount,
    @SessionExpiresAt = ExpiresAt
FROM dbo.VerificationFlows
WHERE UniqueId = @FlowUniqueId AND IsDeleted = 0 AND Status = 'pending';

-- Якщо потік не знайдено або він неактивний, одразу виходимо
IF @SessionExpiresAt IS NULL
BEGIN
        SET @Outcome = 'flow_not_found_or_invalid';
SELECT @Outcome AS Outcome;
RETURN;
END

    -- Крок 2: Отримуємо час останнього створеного OTP для цього потоку
SELECT @LastOtpTimestamp = MAX(CreatedAt)
FROM dbo.OtpRecords
WHERE FlowUniqueId = @FlowUniqueId;

-- Крок 3: Виконуємо всі бізнес-перевірки послідовно
IF @CurrentTime >= @SessionExpiresAt
BEGIN
UPDATE dbo.VerificationFlows SET Status = 'expired' WHERE UniqueId = @FlowUniqueId;
SET @Outcome = 'flow_expired';
END
ELSE IF @OtpCount >= @MaxOtpAttempts
BEGIN
UPDATE dbo.VerificationFlows SET Status = 'failed' WHERE UniqueId = @FlowUniqueId;
SET @Outcome = 'max_otp_attempts_reached';
END
ELSE IF @LastOtpTimestamp IS NOT NULL AND DATEDIFF(second, @LastOtpTimestamp, @CurrentTime) < @MinResendIntervalSeconds
BEGIN
        SET @Outcome = 'resend_cooldown_active';
END
ELSE
BEGIN
        SET @Outcome = 'resend_allowed';
END

    -- Повертаємо фінальний результат
SELECT @Outcome AS Outcome;
END;
go

--------------------------------------------------------------------------------
-- Процедура: UpdateMembershipSecureKey
-- Призначення: Оновлює SecureKey для існуючого членства.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.UpdateMembershipSecureKey
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
go

--------------------------------------------------------------------------------
-- SP: UpdateOtpStatus
-- Призначення: Оновлює статус конкретного OTP.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.UpdateOtpStatus
    @OtpUniqueId UNIQUEIDENTIFIER, @NewStatus NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @CurrentStatus NVARCHAR(20), @FlowId BIGINT, @FlowUniqueId UNIQUEIDENTIFIER;

SELECT @CurrentStatus = o.Status, @FlowId = vf.Id, @FlowUniqueId = vf.UniqueId
FROM dbo.OtpRecords AS o JOIN dbo.VerificationFlows AS vf ON o.FlowUniqueId = vf.UniqueId
WHERE o.UniqueId = @OtpUniqueId AND o.IsDeleted = 0 AND vf.IsDeleted = 0 AND vf.Status = 'pending' AND vf.ExpiresAt > GETUTCDATE();

IF @@ROWCOUNT = 0 BEGIN SELECT CAST(0 AS BIT) AS Success, 'OTP not found, deleted, or flow invalid/expired' AS Message; RETURN; END
    IF @CurrentStatus = 'expired' AND @NewStatus = 'pending' BEGIN SELECT CAST(0 AS BIT) AS Success, 'Cannot transition from expired to pending' AS Message; RETURN; END

UPDATE dbo.OtpRecords SET Status = @NewStatus, IsActive = CASE WHEN @NewStatus = 'pending' THEN 1 ELSE 0 END WHERE UniqueId = @OtpUniqueId AND IsDeleted = 0;
IF @@ROWCOUNT = 0 BEGIN SELECT CAST(0 AS BIT) AS Success, 'Failed to update OTP: no rows affected' AS Message; RETURN; END

    IF @NewStatus = 'failed' INSERT INTO dbo.FailedOtpAttempts (OtpUniqueId, FlowUniqueId) VALUES (@OtpUniqueId, @FlowUniqueId);
ELSE IF @NewStatus = 'verified' UPDATE dbo.VerificationFlows SET Status = 'verified' WHERE Id = @FlowId;

SELECT CAST(1 AS BIT) AS Success, 'OTP status updated successfully' AS Message;
END;
go

--------------------------------------------------------------------------------
-- SP: UpdateVerificationFlowStatus
-- Призначення: Оновлює статус потоку верифікації.
--------------------------------------------------------------------------------
CREATE PROCEDURE dbo.UpdateVerificationFlowStatus
    @FlowUniqueId UNIQUEIDENTIFIER, @NewStatus NVARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;
UPDATE dbo.VerificationFlows
SET Status = @NewStatus, ExpiresAt = CASE WHEN @NewStatus = 'verified' THEN DATEADD(hour, 24, GETUTCDATE()) ELSE ExpiresAt END
WHERE UniqueId = @FlowUniqueId AND IsDeleted = 0;
SELECT @@ROWCOUNT AS RowsAffected;
END;
go

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
go

