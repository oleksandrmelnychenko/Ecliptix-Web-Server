/*
================================================================================
ECLIPTIX DATABASE COMPLETE RESET SCRIPT
================================================================================
Purpose: Drop all tables and recreate the database structure
Database: EcliptixMemberships (SQL Server)
================================================================================
*/

USE [EcliptixMemberships];
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

BEGIN TRY
    BEGIN TRANSACTION DatabaseReset;

    -- ============================================================================
    -- STEP 1: DROP ALL FOREIGN KEY CONSTRAINTS
    -- ============================================================================

    DECLARE @sql NVARCHAR(MAX) = '';

    -- Drop all foreign key constraints
    SELECT @sql = @sql + 'ALTER TABLE [' + SCHEMA_NAME(t.schema_id) + '].[' + t.name + '] DROP CONSTRAINT [' + fk.name + '];' + CHAR(13)
    FROM sys.foreign_keys fk
    INNER JOIN sys.tables t ON fk.parent_object_id = t.object_id;

    IF LEN(@sql) > 0 EXEC sp_executesql @sql;

    -- ============================================================================
    -- STEP 2: DROP ALL TABLES
    -- ============================================================================

    SET @sql = '';

    -- Get all user tables and drop them
    SELECT @sql = @sql + 'DROP TABLE [' + SCHEMA_NAME(schema_id) + '].[' + name + '];' + CHAR(13)
    FROM sys.tables
    WHERE type = 'U'
      AND name NOT LIKE 'sys%'
      AND name NOT LIKE '__EF%';

    IF LEN(@sql) > 0 EXEC sp_executesql @sql;

    -- ============================================================================
    -- STEP 3: RECREATE ALL TABLES FROM INIT SCRIPT
    -- ============================================================================

    -- EventLog
    CREATE TABLE EventLog (
        Id bigint identity PRIMARY KEY,
        EventType nvarchar(50) NOT NULL,
        Message nvarchar(max) NOT NULL,
        CreatedAt datetime2 DEFAULT getutcdate() NOT NULL
    );

    -- AppDevices
    CREATE TABLE AppDevices (
        Id bigint identity PRIMARY KEY,
        AppInstanceId uniqueidentifier NOT NULL,
        DeviceId uniqueidentifier NOT NULL CONSTRAINT UQ_AppDevices_DeviceId UNIQUE,
        DeviceType int CONSTRAINT DF_AppDevices_DeviceType DEFAULT 1 NOT NULL,
        CreatedAt datetime2 CONSTRAINT DF_AppDevices_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_AppDevices_UpdatedAt DEFAULT getutcdate() NOT NULL,
        IsDeleted bit CONSTRAINT DF_AppDevices_IsDeleted DEFAULT 0 NOT NULL,
        UniqueId uniqueidentifier CONSTRAINT DF_AppDevices_UniqueId DEFAULT newid() NOT NULL
            CONSTRAINT UQ_AppDevices_UniqueId UNIQUE
    );

    CREATE INDEX IX_AppDevices_AppInstanceId ON AppDevices (AppInstanceId);

    -- PhoneNumbers
    CREATE TABLE PhoneNumbers (
        Id bigint identity PRIMARY KEY,
        PhoneNumber nvarchar(18) NOT NULL,
        Region nvarchar(2),
        CreatedAt datetime2 CONSTRAINT DF_PhoneNumbers_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_PhoneNumbers_UpdatedAt DEFAULT getutcdate() NOT NULL,
        IsDeleted bit CONSTRAINT DF_PhoneNumbers_IsDeleted DEFAULT 0 NOT NULL,
        UniqueId uniqueidentifier CONSTRAINT DF_PhoneNumbers_UniqueId DEFAULT newid() NOT NULL
            CONSTRAINT UQ_PhoneNumbers_UniqueId UNIQUE,
        CONSTRAINT UQ_PhoneNumbers_ActiveNumberRegion UNIQUE (PhoneNumber, Region, IsDeleted)
    );

    CREATE INDEX IX_PhoneNumbers_PhoneNumber_Region ON PhoneNumbers (PhoneNumber, Region);

    -- PhoneNumberDevices
    CREATE TABLE PhoneNumberDevices (
        PhoneNumberId uniqueidentifier NOT NULL,
        AppDeviceId uniqueidentifier NOT NULL,
        IsPrimary bit CONSTRAINT DF_PhoneNumberDevices_IsPrimary DEFAULT 0 NOT NULL,
        CreatedAt datetime2 CONSTRAINT DF_PhoneNumberDevices_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_PhoneNumberDevices_UpdatedAt DEFAULT getutcdate() NOT NULL,
        IsDeleted bit CONSTRAINT DF_PhoneNumberDevices_IsDeleted DEFAULT 0 NOT NULL,
        CONSTRAINT PK_PhoneNumberDevices PRIMARY KEY (PhoneNumberId, AppDeviceId),
        CONSTRAINT FK_PhoneNumberDevices_PhoneNumbers FOREIGN KEY (PhoneNumberId)
            REFERENCES PhoneNumbers (UniqueId) ON DELETE CASCADE,
        CONSTRAINT FK_PhoneNumberDevices_AppDevices FOREIGN KEY (AppDeviceId)
            REFERENCES AppDevices (UniqueId) ON DELETE CASCADE
    );

    CREATE INDEX IX_PhoneNumberDevices_AppDeviceId ON PhoneNumberDevices (AppDeviceId);

    -- VerificationFlows
    CREATE TABLE VerificationFlows (
        Id bigint identity PRIMARY KEY,
        PhoneNumberId bigint NOT NULL,
        AppDeviceId uniqueidentifier NOT NULL,
        Status nvarchar(20) CONSTRAINT DF_VerificationFlows_Status DEFAULT 'pending' NOT NULL
            CONSTRAINT CHK_VerificationFlows_Status
            CHECK (Status IN ('failed', 'expired', 'verified', 'pending')),
        Purpose nvarchar(30) CONSTRAINT DF_VerificationFlows_Purpose DEFAULT 'unspecified' NOT NULL
            CONSTRAINT CHK_VerificationFlows_Purpose
            CHECK (Purpose IN ('update_phone', 'password_recovery', 'login', 'registration', 'unspecified')),
        ExpiresAt datetime2 NOT NULL,
        OtpCount smallint CONSTRAINT DF_VerificationFlows_OtpCount DEFAULT 0 NOT NULL
            CONSTRAINT CHK_VerificationFlows_OtpCount CHECK (OtpCount >= 0),
        ConnectionId bigint,
        CreatedAt datetime2 CONSTRAINT DF_VerificationFlows_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_VerificationFlows_UpdatedAt DEFAULT getutcdate() NOT NULL,
        IsDeleted bit CONSTRAINT DF_VerificationFlows_IsDeleted DEFAULT 0 NOT NULL,
        UniqueId uniqueidentifier CONSTRAINT DF_VerificationFlows_UniqueId DEFAULT newid() NOT NULL
            CONSTRAINT UQ_VerificationFlows_UniqueId UNIQUE,
        CONSTRAINT FK_VerificationFlows_PhoneNumbers FOREIGN KEY (PhoneNumberId)
            REFERENCES PhoneNumbers (Id) ON DELETE CASCADE,
        CONSTRAINT FK_VerificationFlows_AppDevices FOREIGN KEY (AppDeviceId)
            REFERENCES AppDevices (UniqueId) ON DELETE CASCADE
    );

    CREATE INDEX IX_VerificationFlows_PhoneNumberId_Status ON VerificationFlows (PhoneNumberId, Status);
    CREATE UNIQUE INDEX UQ_VerificationFlows_Pending ON VerificationFlows (AppDeviceId, PhoneNumberId, Purpose)
        WHERE Status = 'pending' AND IsDeleted = 0;

    -- OtpRecords
    CREATE TABLE OtpRecords (
        Id bigint identity PRIMARY KEY,
        FlowUniqueId uniqueidentifier NOT NULL,
        PhoneNumberId bigint NOT NULL,
        OtpHash nvarchar(255) NOT NULL,
        OtpSalt nvarchar(255) NOT NULL,
        ExpiresAt datetime2 NOT NULL,
        Status nvarchar(20) CONSTRAINT DF_OtpRecords_Status DEFAULT 'pending' NOT NULL
            CONSTRAINT CHK_OtpRecords_Status
            CHECK (Status IN ('failed', 'expired', 'verified', 'pending')),
        IsActive bit CONSTRAINT DF_OtpRecords_IsActive DEFAULT 1 NOT NULL,
        CreatedAt datetime2 CONSTRAINT DF_OtpRecords_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_OtpRecords_UpdatedAt DEFAULT getutcdate() NOT NULL,
        IsDeleted bit CONSTRAINT DF_OtpRecords_IsDeleted DEFAULT 0 NOT NULL,
        UniqueId uniqueidentifier CONSTRAINT DF_OtpRecords_UniqueId DEFAULT newid() NOT NULL
            CONSTRAINT UQ_OtpRecords_UniqueId UNIQUE,
        CONSTRAINT FK_OtpRecords_VerificationFlows FOREIGN KEY (FlowUniqueId)
            REFERENCES VerificationFlows (UniqueId) ON DELETE CASCADE,
        CONSTRAINT FK_OtpRecords_PhoneNumbers FOREIGN KEY (PhoneNumberId)
            REFERENCES PhoneNumbers (Id)
    );

    CREATE INDEX IX_OtpRecords_FlowUniqueId_Status ON OtpRecords (FlowUniqueId, Status);

    -- FailedOtpAttempts
    CREATE TABLE FailedOtpAttempts (
        Id bigint identity PRIMARY KEY,
        OtpUniqueId uniqueidentifier NOT NULL,
        FlowUniqueId uniqueidentifier NOT NULL,
        AttemptTime datetime2 CONSTRAINT DF_FailedOtpAttempts_AttemptTime DEFAULT getutcdate() NOT NULL,
        CreatedAt datetime2 CONSTRAINT DF_FailedOtpAttempts_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_FailedOtpAttempts_UpdatedAt DEFAULT getutcdate() NOT NULL,
        IsDeleted bit CONSTRAINT DF_FailedOtpAttempts_IsDeleted DEFAULT 0 NOT NULL,
        CONSTRAINT FK_FailedOtpAttempts_OtpRecords FOREIGN KEY (OtpUniqueId)
            REFERENCES OtpRecords (UniqueId) ON DELETE CASCADE,
        CONSTRAINT FK_FailedOtpAttempts_VerificationFlows FOREIGN KEY (FlowUniqueId)
            REFERENCES VerificationFlows (UniqueId)
    );

    CREATE INDEX IX_FailedOtpAttempts_OtpUniqueId ON FailedOtpAttempts (OtpUniqueId);

    -- Memberships
    CREATE TABLE Memberships (
        Id bigint identity PRIMARY KEY,
        PhoneNumberId uniqueidentifier NOT NULL,
        AppDeviceId uniqueidentifier NOT NULL,
        VerificationFlowId uniqueidentifier NOT NULL,
        SecureKey varbinary(max),
        Status nvarchar(20) CONSTRAINT DF_Memberships_Status DEFAULT 'inactive' NOT NULL
            CONSTRAINT CHK_Memberships_Status CHECK (Status IN ('inactive', 'active')),
        CreationStatus nvarchar(20)
            CONSTRAINT CHK_Memberships_CreationStatus
            CHECK (CreationStatus IN ('passphrase_set', 'secure_key_set', 'otp_verified')),
        CreatedAt datetime2 CONSTRAINT DF_Memberships_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_Memberships_UpdatedAt DEFAULT getutcdate() NOT NULL,
        IsDeleted bit CONSTRAINT DF_Memberships_IsDeleted DEFAULT 0 NOT NULL,
        UniqueId uniqueidentifier CONSTRAINT DF_Memberships_UniqueId DEFAULT newid() NOT NULL
            CONSTRAINT UQ_Memberships_UniqueId UNIQUE,
        CONSTRAINT UQ_Memberships_ActiveMembership UNIQUE (PhoneNumberId, AppDeviceId, IsDeleted),
        CONSTRAINT FK_Memberships_PhoneNumbers FOREIGN KEY (PhoneNumberId)
            REFERENCES PhoneNumbers (UniqueId),
        CONSTRAINT FK_Memberships_AppDevices FOREIGN KEY (AppDeviceId)
            REFERENCES AppDevices (UniqueId),
        CONSTRAINT FK_Memberships_VerificationFlows FOREIGN KEY (VerificationFlowId)
            REFERENCES VerificationFlows (UniqueId)
    );

    CREATE INDEX IX_Memberships_PhoneNumberId_Status ON Memberships (PhoneNumberId, Status);

    -- LoginAttempts
    CREATE TABLE LoginAttempts (
        Id bigint identity PRIMARY KEY,
        Timestamp datetime2 CONSTRAINT DF_LoginAttempts_Timestamp DEFAULT getutcdate() NOT NULL,
        PhoneNumber nvarchar(18) NOT NULL,
        Outcome nvarchar(255) NOT NULL,
        IsSuccess bit CONSTRAINT DF_LoginAttempts_IsSuccess DEFAULT 0 NOT NULL,
        CreatedAt datetime2 CONSTRAINT DF_LoginAttempts_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_LoginAttempts_UpdatedAt DEFAULT getutcdate() NOT NULL
    );

    CREATE INDEX IX_LoginAttempts_PhoneNumber_Timestamp ON LoginAttempts (PhoneNumber, Timestamp);

    -- MembershipAttempts
    CREATE TABLE MembershipAttempts (
        Id bigint identity PRIMARY KEY,
        PhoneNumberId uniqueidentifier NOT NULL,
        Timestamp datetime2 CONSTRAINT DF_MembershipAttempts_Timestamp DEFAULT getutcdate() NOT NULL,
        Outcome nvarchar(255) NOT NULL,
        IsSuccess bit CONSTRAINT DF_MembershipAttempts_IsSuccess DEFAULT 0 NOT NULL,
        CreatedAt datetime2 CONSTRAINT DF_MembershipAttempts_CreatedAt DEFAULT getutcdate() NOT NULL,
        UpdatedAt datetime2 CONSTRAINT DF_MembershipAttempts_UpdatedAt DEFAULT getutcdate() NOT NULL,
        IsDeleted bit CONSTRAINT DF_MembershipAttempts_IsDeleted DEFAULT 0 NOT NULL,
        CONSTRAINT FK_MembershipAttempts_PhoneNumbers FOREIGN KEY (PhoneNumberId)
            REFERENCES PhoneNumbers (UniqueId) ON DELETE CASCADE
    );

    CREATE INDEX IX_MembershipAttempts_PhoneNumberId_Timestamp ON MembershipAttempts (PhoneNumberId, Timestamp);

    -- Akka.NET Persistence Tables
    CREATE TABLE Metadata (
        PersistenceId nvarchar(255) NOT NULL,
        SequenceNr bigint NOT NULL,
        CONSTRAINT PK_Metadata PRIMARY KEY (PersistenceId, SequenceNr)
    );

    CREATE TABLE journal (
        ordering bigint identity CONSTRAINT PK_journal PRIMARY KEY,
        created bigint NOT NULL,
        deleted bit NOT NULL,
        persistence_id nvarchar(255) NOT NULL,
        sequence_number bigint NOT NULL,
        message varbinary(max) NOT NULL,
        manifest nvarchar(500),
        identifier int,
        writer_uuid nvarchar(128),
        CONSTRAINT UQ_journal UNIQUE (persistence_id, sequence_number)
    );

    CREATE INDEX IX_journal_sequence_number ON journal (sequence_number);
    CREATE INDEX IX_journal_created ON journal (created);

    CREATE TABLE snapshot (
        persistence_id nvarchar(255) NOT NULL,
        sequence_number bigint NOT NULL,
        created datetime2 NOT NULL,
        snapshot varbinary(max),
        manifest nvarchar(500),
        serializer_id int,
        CONSTRAINT PK_snapshot PRIMARY KEY (persistence_id, sequence_number)
    );

    CREATE INDEX IX_snapshot_sequence_number ON snapshot (sequence_number);
    CREATE INDEX IX_snapshot_created ON snapshot (created);

    CREATE TABLE tags (
        ordering_id bigint NOT NULL,
        tag nvarchar(64) NOT NULL,
        sequence_nr bigint NOT NULL,
        persistence_id varchar(255) NOT NULL,
        PRIMARY KEY (ordering_id, tag, persistence_id)
    );

    CREATE INDEX IX_tags_persistence_id_sequence_nr ON tags (persistence_id, sequence_nr);
    CREATE INDEX IX_tags_tag ON tags (tag);

    -- ============================================================================
    -- STEP 4: CREATE TRIGGERS
    -- ============================================================================

    -- AppDevices Update Trigger
    EXEC('CREATE TRIGGER TRG_AppDevices_Update ON dbo.AppDevices FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.AppDevices t
        INNER JOIN inserted i ON t.Id = i.Id;
    END');

    -- PhoneNumbers Update Trigger
    EXEC('CREATE TRIGGER TRG_PhoneNumbers_Update ON dbo.PhoneNumbers FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.PhoneNumbers t
        INNER JOIN inserted i ON t.Id = i.Id;
    END');

    -- PhoneNumberDevices Update Trigger
    EXEC('CREATE TRIGGER TRG_PhoneNumberDevices_Update ON dbo.PhoneNumberDevices FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.PhoneNumberDevices t
        INNER JOIN inserted i ON t.PhoneNumberId = i.PhoneNumberId AND t.AppDeviceId = i.AppDeviceId;
    END');

    -- VerificationFlows Update Trigger
    EXEC('CREATE TRIGGER TRG_VerificationFlows_Update ON dbo.VerificationFlows FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.VerificationFlows t
        INNER JOIN inserted i ON t.Id = i.Id;
    END');

    -- OtpRecords Update Trigger
    EXEC('CREATE TRIGGER TRG_OtpRecords_Update ON dbo.OtpRecords FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.OtpRecords t
        INNER JOIN inserted i ON t.Id = i.Id;
    END');

    -- FailedOtpAttempts Update Trigger
    EXEC('CREATE TRIGGER TRG_FailedOtpAttempts_Update ON dbo.FailedOtpAttempts FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.FailedOtpAttempts t
        INNER JOIN inserted i ON t.Id = i.Id;
    END');

    -- Memberships Update Trigger
    EXEC('CREATE TRIGGER TRG_Memberships_Update ON dbo.Memberships FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.Memberships t
        INNER JOIN inserted i ON t.Id = i.Id;
    END');

    -- LoginAttempts Update Trigger
    EXEC('CREATE TRIGGER TRG_LoginAttempts_Update ON dbo.LoginAttempts FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.LoginAttempts t
        INNER JOIN inserted i ON t.Id = i.Id;
    END');

    -- MembershipAttempts Update Trigger
    EXEC('CREATE TRIGGER TRG_MembershipAttempts_Update ON dbo.MembershipAttempts FOR UPDATE AS
    BEGIN
        SET NOCOUNT ON;
        IF UPDATE(UpdatedAt) RETURN;
        UPDATE t SET UpdatedAt = GETUTCDATE()
        FROM dbo.MembershipAttempts t
        INNER JOIN inserted i ON t.Id = i.Id;
    END');

    COMMIT TRANSACTION DatabaseReset;

END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION DatabaseReset;
    THROW;
END CATCH
GO