/*
================================================================================
Layer 2.1: Core Domain Tables
================================================================================
Purpose: Core business domain tables for authentication, verification, and membership
Dependencies: Layer 1 (Configuration & Core Infrastructure)
Execution Order: 6th - Foundation tables for all business operations

Features:
- AppDevices: Device registration and management
- PhoneNumbers: Phone number management with region support
- PhoneNumberDevices: Device-phone relationships
- VerificationFlows: Verification workflow management
- OtpRecords: OTP lifecycle and security
- Memberships: User membership management
- Authentication: Context and state management
- Auditing: Activity tracking tables

Author: Ecliptix Development Team
Version: 1.0.0
Created: 2024-08-24
================================================================================
*/

-- Use target database
USE [EcliptixMemberships]; -- Replace with your actual database name
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;
GO

PRINT '================================================================================';
PRINT 'Layer 2.1: Core Domain Tables';
PRINT 'Started at: ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 121);
PRINT '================================================================================';

-- Log deployment start
DECLARE @DeploymentId UNIQUEIDENTIFIER = (
    SELECT TOP 1 DeploymentId 
    FROM dbo.DeploymentLog 
    WHERE Status = 'COMPLETED' 
    ORDER BY CreatedAt DESC
);

INSERT INTO dbo.DeploymentLog (DeploymentId, ScriptName, ExecutionOrder, Status)
VALUES (@DeploymentId, '01_CoreDomainTables.sql', 5, 'RUNNING');

DECLARE @LogId BIGINT = SCOPE_IDENTITY();

BEGIN TRY
    BEGIN TRANSACTION;
    
    -- ============================================================================
    -- CLEANUP EXISTING OBJECTS
    -- ============================================================================
    
    PRINT 'Cleaning up existing objects...';
    
    -- Drop tables in reverse dependency order
    IF OBJECT_ID('dbo.MembershipAttempts', 'U') IS NOT NULL DROP TABLE dbo.MembershipAttempts;
    IF OBJECT_ID('dbo.LoginAttempts', 'U') IS NOT NULL DROP TABLE dbo.LoginAttempts;
    IF OBJECT_ID('dbo.AuthenticationStates', 'U') IS NOT NULL DROP TABLE dbo.AuthenticationStates;
    IF OBJECT_ID('dbo.AuthenticationContexts', 'U') IS NOT NULL DROP TABLE dbo.AuthenticationContexts;
    IF OBJECT_ID('dbo.Memberships', 'U') IS NOT NULL DROP TABLE dbo.Memberships;
    IF OBJECT_ID('dbo.FailedOtpAttempts', 'U') IS NOT NULL DROP TABLE dbo.FailedOtpAttempts;
    IF OBJECT_ID('dbo.OtpRecords', 'U') IS NOT NULL DROP TABLE dbo.OtpRecords;
    IF OBJECT_ID('dbo.PhoneNumberDevices', 'U') IS NOT NULL DROP TABLE dbo.PhoneNumberDevices;
    IF OBJECT_ID('dbo.VerificationFlows', 'U') IS NOT NULL DROP TABLE dbo.VerificationFlows;
    IF OBJECT_ID('dbo.PhoneNumbers', 'U') IS NOT NULL DROP TABLE dbo.PhoneNumbers;
    IF OBJECT_ID('dbo.AppDevices', 'U') IS NOT NULL DROP TABLE dbo.AppDevices;
    IF OBJECT_ID('dbo.EventLog', 'U') IS NOT NULL DROP TABLE dbo.EventLog;
    
    PRINT '✓ Existing objects cleaned up';
    
    -- ============================================================================
    -- DEVICE MANAGEMENT TABLES
    -- ============================================================================
    
    PRINT 'Creating device management tables...';
    
    -- AppDevices: Core device registration and management
    CREATE TABLE dbo.AppDevices (
        Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
        AppInstanceId   UNIQUEIDENTIFIER NOT NULL,
        DeviceId        UNIQUEIDENTIFIER NOT NULL,
        DeviceType      INT NOT NULL CONSTRAINT DF_AppDevices_DeviceType DEFAULT 1,
        CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_AppDevices_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_AppDevices_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted       BIT NOT NULL CONSTRAINT DF_AppDevices_IsDeleted DEFAULT 0,
        UniqueId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_AppDevices_UniqueId DEFAULT NEWID(),
        
        -- Constraints
        CONSTRAINT UQ_AppDevices_UniqueId UNIQUE (UniqueId),
        CONSTRAINT UQ_AppDevices_DeviceId UNIQUE (DeviceId),
        CONSTRAINT CHK_AppDevices_DeviceType CHECK (DeviceType IN (1, 2, 3, 4)) -- 1=Mobile, 2=Tablet, 3=Desktop, 4=Web
    );
    
    -- Indexes for performance
    CREATE NONCLUSTERED INDEX IX_AppDevices_AppInstanceId ON dbo.AppDevices (AppInstanceId);
    CREATE NONCLUSTERED INDEX IX_AppDevices_DeviceType ON dbo.AppDevices (DeviceType);
    CREATE NONCLUSTERED INDEX IX_AppDevices_IsDeleted_CreatedAt ON dbo.AppDevices (IsDeleted, CreatedAt);
    
    PRINT '✓ AppDevices table created successfully';
    
    -- ============================================================================
    -- PHONE NUMBER MANAGEMENT
    -- ============================================================================
    
    PRINT 'Creating phone number management tables...';
    
    -- PhoneNumbers: Phone number registry with regional support
    CREATE TABLE dbo.PhoneNumbers (
        Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
        PhoneNumber     NVARCHAR(18) NOT NULL,
        Region          NVARCHAR(2), -- ISO 3166-1 alpha-2 country code
        CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_PhoneNumbers_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_PhoneNumbers_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted       BIT NOT NULL CONSTRAINT DF_PhoneNumbers_IsDeleted DEFAULT 0,
        UniqueId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_PhoneNumbers_UniqueId DEFAULT NEWID(),
        
        -- Constraints
        CONSTRAINT UQ_PhoneNumbers_UniqueId UNIQUE (UniqueId),
        CONSTRAINT UQ_PhoneNumbers_ActiveNumberRegion UNIQUE (PhoneNumber, Region, IsDeleted),
        CONSTRAINT CHK_PhoneNumbers_PhoneNumber_Length CHECK (LEN(TRIM(PhoneNumber)) BETWEEN 7 AND 18),
        CONSTRAINT CHK_PhoneNumbers_Region_Format CHECK (Region IS NULL OR LEN(Region) = 2)
    );
    
    -- Indexes for efficient queries
    CREATE NONCLUSTERED INDEX IX_PhoneNumbers_PhoneNumber_Region ON dbo.PhoneNumbers (PhoneNumber, Region);
    CREATE NONCLUSTERED INDEX IX_PhoneNumbers_Region ON dbo.PhoneNumbers (Region) WHERE Region IS NOT NULL;
    CREATE NONCLUSTERED INDEX IX_PhoneNumbers_IsDeleted_CreatedAt ON dbo.PhoneNumbers (IsDeleted, CreatedAt);
    
    PRINT '✓ PhoneNumbers table created successfully';
    
    -- PhoneNumberDevices: Many-to-many relationship between phones and devices
    CREATE TABLE dbo.PhoneNumberDevices (
        PhoneNumberId   UNIQUEIDENTIFIER NOT NULL, -- References PhoneNumbers.UniqueId
        AppDeviceId     UNIQUEIDENTIFIER NOT NULL, -- References AppDevices.UniqueId
        IsPrimary       BIT NOT NULL CONSTRAINT DF_PhoneNumberDevices_IsPrimary DEFAULT 0,
        CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_PhoneNumberDevices_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_PhoneNumberDevices_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted       BIT NOT NULL CONSTRAINT DF_PhoneNumberDevices_IsDeleted DEFAULT 0,
        
        -- Composite primary key
        CONSTRAINT PK_PhoneNumberDevices PRIMARY KEY (PhoneNumberId, AppDeviceId),
        
        -- Foreign key constraints (will be added in Layer 3: Relationships)
        CONSTRAINT FK_PhoneNumberDevices_PhoneNumbers FOREIGN KEY (PhoneNumberId) 
            REFERENCES dbo.PhoneNumbers(UniqueId) ON DELETE CASCADE,
        CONSTRAINT FK_PhoneNumberDevices_AppDevices FOREIGN KEY (AppDeviceId) 
            REFERENCES dbo.AppDevices(UniqueId) ON DELETE CASCADE
    );
    
    -- Indexes for relationship queries
    CREATE NONCLUSTERED INDEX IX_PhoneNumberDevices_AppDeviceId ON dbo.PhoneNumberDevices (AppDeviceId);
    CREATE NONCLUSTERED INDEX IX_PhoneNumberDevices_IsPrimary ON dbo.PhoneNumberDevices (IsPrimary) WHERE IsPrimary = 1;
    CREATE NONCLUSTERED INDEX IX_PhoneNumberDevices_IsDeleted_CreatedAt ON dbo.PhoneNumberDevices (IsDeleted, CreatedAt);
    
    PRINT '✓ PhoneNumberDevices table created successfully';
    
    -- ============================================================================
    -- VERIFICATION WORKFLOW TABLES
    -- ============================================================================
    
    PRINT 'Creating verification workflow tables...';
    
    -- VerificationFlows: Core verification workflow management
    CREATE TABLE dbo.VerificationFlows (
        Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
        PhoneNumberId   BIGINT NOT NULL, -- References PhoneNumbers.Id
        AppDeviceId     UNIQUEIDENTIFIER NOT NULL, -- References AppDevices.UniqueId
        Status          NVARCHAR(20) NOT NULL CONSTRAINT DF_VerificationFlows_Status DEFAULT 'pending',
        Purpose         NVARCHAR(30) NOT NULL CONSTRAINT DF_VerificationFlows_Purpose DEFAULT 'unspecified',
        ExpiresAt       DATETIME2(7) NOT NULL,
        OtpCount        SMALLINT NOT NULL CONSTRAINT DF_VerificationFlows_OtpCount DEFAULT 0,
        ConnectionId    BIGINT, -- Optional connection identifier for real-time tracking
        CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_VerificationFlows_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_VerificationFlows_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted       BIT NOT NULL CONSTRAINT DF_VerificationFlows_IsDeleted DEFAULT 0,
        UniqueId        UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_VerificationFlows_UniqueId DEFAULT NEWID(),
        
        -- Constraints
        CONSTRAINT UQ_VerificationFlows_UniqueId UNIQUE (UniqueId),
        CONSTRAINT CHK_VerificationFlows_Status CHECK (Status IN ('pending', 'verified', 'expired', 'failed')),
        CONSTRAINT CHK_VerificationFlows_Purpose CHECK (Purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'update_phone')),
        CONSTRAINT CHK_VerificationFlows_OtpCount CHECK (OtpCount >= 0 AND OtpCount <= 100),
        CONSTRAINT CHK_VerificationFlows_ExpiresAt CHECK (ExpiresAt > CreatedAt),
        
        -- Foreign key constraints
        CONSTRAINT FK_VerificationFlows_PhoneNumbers FOREIGN KEY (PhoneNumberId) 
            REFERENCES dbo.PhoneNumbers(Id) ON DELETE CASCADE,
        CONSTRAINT FK_VerificationFlows_AppDevices FOREIGN KEY (AppDeviceId) 
            REFERENCES dbo.AppDevices(UniqueId) ON DELETE CASCADE
    );
    
    -- Indexes for workflow queries
    CREATE NONCLUSTERED INDEX IX_VerificationFlows_PhoneNumberId_Status ON dbo.VerificationFlows (PhoneNumberId, Status);
    CREATE NONCLUSTERED INDEX IX_VerificationFlows_AppDeviceId_Status ON dbo.VerificationFlows (AppDeviceId, Status);
    CREATE NONCLUSTERED INDEX IX_VerificationFlows_ExpiresAt ON dbo.VerificationFlows (ExpiresAt) WHERE Status = 'pending';
    CREATE NONCLUSTERED INDEX IX_VerificationFlows_Purpose ON dbo.VerificationFlows (Purpose);
    
    -- Unique constraint to prevent duplicate active flows
    CREATE UNIQUE INDEX UQ_VerificationFlows_Pending 
        ON dbo.VerificationFlows (AppDeviceId, PhoneNumberId, Purpose) 
        WHERE (Status = 'pending' AND IsDeleted = 0);
    
    PRINT '✓ VerificationFlows table created successfully';
    
    -- ============================================================================
    -- OTP MANAGEMENT TABLES
    -- ============================================================================
    
    PRINT 'Creating OTP management tables...';
    
    -- OtpRecords: Secure OTP storage and lifecycle management
    CREATE TABLE dbo.OtpRecords (
        Id                BIGINT IDENTITY(1,1) PRIMARY KEY,
        FlowUniqueId      UNIQUEIDENTIFIER NOT NULL, -- References VerificationFlows.UniqueId
        PhoneNumberId     BIGINT NOT NULL, -- References PhoneNumbers.Id
        OtpHash           NVARCHAR(255) NOT NULL, -- Hashed OTP for security
        OtpSalt           NVARCHAR(255) NOT NULL, -- Salt for OTP hashing
        ExpiresAt         DATETIME2(7) NOT NULL,
        Status            NVARCHAR(20) NOT NULL CONSTRAINT DF_OtpRecords_Status DEFAULT 'pending',
        IsActive          BIT NOT NULL CONSTRAINT DF_OtpRecords_IsActive DEFAULT 1,
        CreatedAt         DATETIME2(7) NOT NULL CONSTRAINT DF_OtpRecords_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt         DATETIME2(7) NOT NULL CONSTRAINT DF_OtpRecords_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted         BIT NOT NULL CONSTRAINT DF_OtpRecords_IsDeleted DEFAULT 0,
        UniqueId          UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_OtpRecords_UniqueId DEFAULT NEWID(),
        
        -- Constraints
        CONSTRAINT UQ_OtpRecords_UniqueId UNIQUE (UniqueId),
        CONSTRAINT CHK_OtpRecords_Status CHECK (Status IN ('pending', 'verified', 'expired', 'failed')),
        CONSTRAINT CHK_OtpRecords_ExpiresAt CHECK (ExpiresAt > CreatedAt),
        CONSTRAINT CHK_OtpRecords_Hash_Length CHECK (LEN(OtpHash) >= 32), -- Minimum hash length
        CONSTRAINT CHK_OtpRecords_Salt_Length CHECK (LEN(OtpSalt) >= 16), -- Minimum salt length
        
        -- Foreign key constraints
        CONSTRAINT FK_OtpRecords_VerificationFlows FOREIGN KEY (FlowUniqueId) 
            REFERENCES dbo.VerificationFlows(UniqueId) ON DELETE CASCADE,
        CONSTRAINT FK_OtpRecords_PhoneNumbers FOREIGN KEY (PhoneNumberId) 
            REFERENCES dbo.PhoneNumbers(Id) ON DELETE NO ACTION
    );
    
    -- Indexes for OTP operations
    CREATE NONCLUSTERED INDEX IX_OtpRecords_FlowUniqueId_Status ON dbo.OtpRecords (FlowUniqueId, Status);
    CREATE NONCLUSTERED INDEX IX_OtpRecords_PhoneNumberId_Status ON dbo.OtpRecords (PhoneNumberId, Status);
    CREATE NONCLUSTERED INDEX IX_OtpRecords_ExpiresAt ON dbo.OtpRecords (ExpiresAt) WHERE IsActive = 1;
    CREATE NONCLUSTERED INDEX IX_OtpRecords_IsActive_Status ON dbo.OtpRecords (IsActive, Status);
    
    PRINT '✓ OtpRecords table created successfully';
    
    -- FailedOtpAttempts: Security tracking for failed OTP attempts
    CREATE TABLE dbo.FailedOtpAttempts (
        Id                BIGINT IDENTITY(1,1) PRIMARY KEY,
        OtpUniqueId       UNIQUEIDENTIFIER NOT NULL, -- References OtpRecords.UniqueId
        FlowUniqueId      UNIQUEIDENTIFIER NOT NULL, -- References VerificationFlows.UniqueId
        AttemptTime       DATETIME2(7) NOT NULL CONSTRAINT DF_FailedOtpAttempts_AttemptTime DEFAULT GETUTCDATE(),
        CreatedAt         DATETIME2(7) NOT NULL CONSTRAINT DF_FailedOtpAttempts_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt         DATETIME2(7) NOT NULL CONSTRAINT DF_FailedOtpAttempts_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted         BIT NOT NULL CONSTRAINT DF_FailedOtpAttempts_IsDeleted DEFAULT 0,
        
        -- Constraints
        CONSTRAINT CHK_FailedOtpAttempts_AttemptTime CHECK (AttemptTime <= GETUTCDATE()),
        
        -- Foreign key constraints
        CONSTRAINT FK_FailedOtpAttempts_OtpRecords FOREIGN KEY (OtpUniqueId) 
            REFERENCES dbo.OtpRecords(UniqueId) ON DELETE CASCADE,
        CONSTRAINT FK_FailedOtpAttempts_VerificationFlows FOREIGN KEY (FlowUniqueId) 
            REFERENCES dbo.VerificationFlows(UniqueId) ON DELETE NO ACTION
    );
    
    -- Indexes for security analysis
    CREATE NONCLUSTERED INDEX IX_FailedOtpAttempts_OtpUniqueId ON dbo.FailedOtpAttempts (OtpUniqueId);
    CREATE NONCLUSTERED INDEX IX_FailedOtpAttempts_FlowUniqueId ON dbo.FailedOtpAttempts (FlowUniqueId);
    CREATE NONCLUSTERED INDEX IX_FailedOtpAttempts_AttemptTime ON dbo.FailedOtpAttempts (AttemptTime);
    
    PRINT '✓ FailedOtpAttempts table created successfully';
    
    -- ============================================================================
    -- MEMBERSHIP MANAGEMENT TABLES
    -- ============================================================================
    
    PRINT 'Creating membership management tables...';
    
    -- Memberships: Core user membership and access management
    CREATE TABLE dbo.Memberships (
        Id                      BIGINT IDENTITY(1,1) PRIMARY KEY,
        PhoneNumberId           UNIQUEIDENTIFIER NOT NULL, -- References PhoneNumbers.UniqueId
        AppDeviceId             UNIQUEIDENTIFIER NOT NULL, -- References AppDevices.UniqueId
        VerificationFlowId      UNIQUEIDENTIFIER NOT NULL, -- References VerificationFlows.UniqueId
        SecureKey               VARBINARY(MAX), -- Encrypted secure key for authentication
        Status                  NVARCHAR(20) NOT NULL CONSTRAINT DF_Memberships_Status DEFAULT 'inactive',
        CreationStatus          NVARCHAR(20),
        CreatedAt               DATETIME2(7) NOT NULL CONSTRAINT DF_Memberships_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt               DATETIME2(7) NOT NULL CONSTRAINT DF_Memberships_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted               BIT NOT NULL CONSTRAINT DF_Memberships_IsDeleted DEFAULT 0,
        UniqueId                UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_Memberships_UniqueId DEFAULT NEWID(),
        
        -- Constraints
        CONSTRAINT UQ_Memberships_UniqueId UNIQUE (UniqueId),
        CONSTRAINT CHK_Memberships_Status CHECK (Status IN ('active', 'inactive', 'suspended', 'locked')),
        CONSTRAINT CHK_Memberships_CreationStatus CHECK (CreationStatus IN ('otp_verified', 'secure_key_set', 'passphrase_set')),
        
        -- Foreign key constraints
        CONSTRAINT FK_Memberships_PhoneNumbers FOREIGN KEY (PhoneNumberId) 
            REFERENCES dbo.PhoneNumbers(UniqueId) ON DELETE NO ACTION,
        CONSTRAINT FK_Memberships_AppDevices FOREIGN KEY (AppDeviceId) 
            REFERENCES dbo.AppDevices(UniqueId) ON DELETE NO ACTION,
        CONSTRAINT FK_Memberships_VerificationFlows FOREIGN KEY (VerificationFlowId) 
            REFERENCES dbo.VerificationFlows(UniqueId) ON DELETE NO ACTION,
        
        -- Unique constraint to prevent duplicate active memberships
        CONSTRAINT UQ_Memberships_ActiveMembership UNIQUE (PhoneNumberId, AppDeviceId, IsDeleted)
    );
    
    -- Indexes for membership queries
    CREATE NONCLUSTERED INDEX IX_Memberships_PhoneNumberId_Status ON dbo.Memberships (PhoneNumberId, Status);
    CREATE NONCLUSTERED INDEX IX_Memberships_AppDeviceId_Status ON dbo.Memberships (AppDeviceId, Status);
    CREATE NONCLUSTERED INDEX IX_Memberships_Status ON dbo.Memberships (Status);
    CREATE NONCLUSTERED INDEX IX_Memberships_CreationStatus ON dbo.Memberships (CreationStatus);
    
    PRINT '✓ Memberships table created successfully';
    
    -- ============================================================================
    -- AUTHENTICATION MANAGEMENT TABLES
    -- ============================================================================
    
    PRINT 'Creating authentication management tables...';
    
    -- AuthenticationContexts: Session-like authentication contexts
    CREATE TABLE dbo.AuthenticationContexts (
        Id                  BIGINT IDENTITY(1,1) PRIMARY KEY,
        ContextToken        VARBINARY(64) NOT NULL UNIQUE, -- Secure authentication token
        MembershipId        UNIQUEIDENTIFIER NOT NULL, -- References Memberships.UniqueId
        MobileNumberId      UNIQUEIDENTIFIER NOT NULL, -- References PhoneNumbers.UniqueId
        CreatedAt           DATETIME2(7) NOT NULL CONSTRAINT DF_AuthContexts_CreatedAt DEFAULT GETUTCDATE(),
        ExpiresAt           DATETIME2(7) NOT NULL,
        LastAccessedAt      DATETIME2(7) NOT NULL CONSTRAINT DF_AuthContexts_LastAccessedAt DEFAULT GETUTCDATE(),
        IsActive            BIT NOT NULL CONSTRAINT DF_AuthContexts_IsActive DEFAULT 1,
        ContextState        NVARCHAR(20) NOT NULL CONSTRAINT DF_AuthContexts_ContextState DEFAULT 'active',
        IpAddress           NVARCHAR(45), -- IPv4/IPv6 address
        UserAgent           NVARCHAR(500), -- Client User Agent
        UpdatedAt           DATETIME2(7) NOT NULL CONSTRAINT DF_AuthContexts_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted           BIT NOT NULL CONSTRAINT DF_AuthContexts_IsDeleted DEFAULT 0,
        
        -- Constraints
        CONSTRAINT CHK_AuthContexts_ContextState CHECK (ContextState IN ('active', 'expired', 'invalidated')),
        CONSTRAINT CHK_AuthContexts_ExpiresAt CHECK (ExpiresAt > CreatedAt),
        CONSTRAINT CHK_AuthContexts_LastAccessedAt CHECK (LastAccessedAt >= CreatedAt),
        CONSTRAINT CHK_AuthContexts_ContextToken_Length CHECK (LEN(ContextToken) >= 32), -- Minimum token length
        
        -- Foreign key constraints
        CONSTRAINT FK_AuthContexts_Memberships FOREIGN KEY (MembershipId) 
            REFERENCES dbo.Memberships(UniqueId) ON DELETE CASCADE,
        CONSTRAINT FK_AuthContexts_MobileNumbers FOREIGN KEY (MobileNumberId) 
            REFERENCES dbo.PhoneNumbers(UniqueId) ON DELETE NO ACTION
    );
    
    -- Indexes for authentication queries
    CREATE NONCLUSTERED INDEX IX_AuthContexts_ContextToken ON dbo.AuthenticationContexts (ContextToken);
    CREATE NONCLUSTERED INDEX IX_AuthContexts_MobileNumberId_Active ON dbo.AuthenticationContexts (MobileNumberId, IsActive);
    CREATE NONCLUSTERED INDEX IX_AuthContexts_MembershipId_Active ON dbo.AuthenticationContexts (MembershipId, IsActive);
    CREATE NONCLUSTERED INDEX IX_AuthContexts_ExpiresAt ON dbo.AuthenticationContexts (ExpiresAt) WHERE IsActive = 1;
    CREATE NONCLUSTERED INDEX IX_AuthContexts_LastAccessedAt ON dbo.AuthenticationContexts (LastAccessedAt);
    
    PRINT '✓ AuthenticationContexts table created successfully';
    
    -- AuthenticationStates: Optimized authentication state tracking
    CREATE TABLE dbo.AuthenticationStates (
        MobileNumberId      UNIQUEIDENTIFIER PRIMARY KEY, -- References PhoneNumbers.UniqueId
        RecentAttempts      INT NOT NULL CONSTRAINT DF_AuthStates_RecentAttempts DEFAULT 0,
        WindowStartTime     DATETIME2(7) NOT NULL CONSTRAINT DF_AuthStates_WindowStartTime DEFAULT GETUTCDATE(),
        LastAttemptTime     DATETIME2(7),
        IsLocked            BIT NOT NULL CONSTRAINT DF_AuthStates_IsLocked DEFAULT 0,
        LockedUntil         DATETIME2(7),
        LastSyncTime        DATETIME2(7) NOT NULL CONSTRAINT DF_AuthStates_LastSyncTime DEFAULT GETUTCDATE(),
        CreatedAt           DATETIME2(7) NOT NULL CONSTRAINT DF_AuthStates_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt           DATETIME2(7) NOT NULL CONSTRAINT DF_AuthStates_UpdatedAt DEFAULT GETUTCDATE(),
        
        -- Constraints
        CONSTRAINT CHK_AuthStates_RecentAttempts CHECK (RecentAttempts >= 0),
        CONSTRAINT CHK_AuthStates_LockedUntil_Logic CHECK (
            (IsLocked = 0 AND LockedUntil IS NULL) OR 
            (IsLocked = 1 AND LockedUntil IS NOT NULL AND LockedUntil > GETUTCDATE())
        ),
        
        -- Foreign key constraints
        CONSTRAINT FK_AuthStates_MobileNumbers FOREIGN KEY (MobileNumberId) 
            REFERENCES dbo.PhoneNumbers(UniqueId) ON DELETE CASCADE
    );
    
    -- Indexes for rate limiting queries
    CREATE NONCLUSTERED INDEX IX_AuthStates_IsLocked_LockedUntil ON dbo.AuthenticationStates (IsLocked, LockedUntil);
    CREATE NONCLUSTERED INDEX IX_AuthStates_LastAttemptTime ON dbo.AuthenticationStates (LastAttemptTime);
    CREATE NONCLUSTERED INDEX IX_AuthStates_RecentAttempts ON dbo.AuthenticationStates (RecentAttempts) WHERE RecentAttempts > 0;
    
    PRINT '✓ AuthenticationStates table created successfully';
    
    -- ============================================================================
    -- ACTIVITY TRACKING TABLES
    -- ============================================================================
    
    PRINT 'Creating activity tracking tables...';
    
    -- LoginAttempts: Login attempt tracking for security analysis
    CREATE TABLE dbo.LoginAttempts (
        Id           BIGINT IDENTITY(1,1) PRIMARY KEY,
        Timestamp    DATETIME2(7) NOT NULL CONSTRAINT DF_LoginAttempts_Timestamp DEFAULT GETUTCDATE(),
        PhoneNumber  NVARCHAR(18) NOT NULL,
        Outcome      NVARCHAR(255) NOT NULL,
        IsSuccess    BIT NOT NULL CONSTRAINT DF_LoginAttempts_IsSuccess DEFAULT 0,
        CreatedAt    DATETIME2(7) NOT NULL CONSTRAINT DF_LoginAttempts_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt    DATETIME2(7) NOT NULL CONSTRAINT DF_LoginAttempts_UpdatedAt DEFAULT GETUTCDATE(),
        
        -- Constraints
        CONSTRAINT CHK_LoginAttempts_PhoneNumber_Length CHECK (LEN(TRIM(PhoneNumber)) BETWEEN 7 AND 18),
        CONSTRAINT CHK_LoginAttempts_Outcome_NotEmpty CHECK (LEN(TRIM(Outcome)) > 0),
        CONSTRAINT CHK_LoginAttempts_Timestamp CHECK (Timestamp <= GETUTCDATE())
    );
    
    -- Indexes for security analysis
    CREATE NONCLUSTERED INDEX IX_LoginAttempts_PhoneNumber_Timestamp ON dbo.LoginAttempts (PhoneNumber, Timestamp);
    CREATE NONCLUSTERED INDEX IX_LoginAttempts_IsSuccess_Timestamp ON dbo.LoginAttempts (IsSuccess, Timestamp);
    CREATE NONCLUSTERED INDEX IX_LoginAttempts_Timestamp ON dbo.LoginAttempts (Timestamp);
    
    PRINT '✓ LoginAttempts table created successfully';
    
    -- MembershipAttempts: Membership creation attempt tracking
    CREATE TABLE dbo.MembershipAttempts (
        Id              BIGINT IDENTITY(1,1) PRIMARY KEY,
        PhoneNumberId   UNIQUEIDENTIFIER NOT NULL, -- References PhoneNumbers.UniqueId
        Timestamp       DATETIME2(7) NOT NULL CONSTRAINT DF_MembershipAttempts_Timestamp DEFAULT GETUTCDATE(),
        Outcome         NVARCHAR(255) NOT NULL,
        IsSuccess       BIT NOT NULL CONSTRAINT DF_MembershipAttempts_IsSuccess DEFAULT 0,
        CreatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_MembershipAttempts_CreatedAt DEFAULT GETUTCDATE(),
        UpdatedAt       DATETIME2(7) NOT NULL CONSTRAINT DF_MembershipAttempts_UpdatedAt DEFAULT GETUTCDATE(),
        IsDeleted       BIT NOT NULL CONSTRAINT DF_MembershipAttempts_IsDeleted DEFAULT 0,
        
        -- Constraints
        CONSTRAINT CHK_MembershipAttempts_Outcome_NotEmpty CHECK (LEN(TRIM(Outcome)) > 0),
        CONSTRAINT CHK_MembershipAttempts_Timestamp CHECK (Timestamp <= GETUTCDATE()),
        
        -- Foreign key constraints
        CONSTRAINT FK_MembershipAttempts_PhoneNumbers FOREIGN KEY (PhoneNumberId) 
            REFERENCES dbo.PhoneNumbers(UniqueId) ON DELETE CASCADE
    );
    
    -- Indexes for membership analysis
    CREATE NONCLUSTERED INDEX IX_MembershipAttempts_PhoneNumberId_Timestamp ON dbo.MembershipAttempts (PhoneNumberId, Timestamp);
    CREATE NONCLUSTERED INDEX IX_MembershipAttempts_IsSuccess_Timestamp ON dbo.MembershipAttempts (IsSuccess, Timestamp);
    CREATE NONCLUSTERED INDEX IX_MembershipAttempts_Timestamp ON dbo.MembershipAttempts (Timestamp);
    
    PRINT '✓ MembershipAttempts table created successfully';
    
    -- EventLog: General event logging for system monitoring
    CREATE TABLE dbo.EventLog (
        Id BIGINT IDENTITY(1,1) PRIMARY KEY,
        EventType NVARCHAR(50) NOT NULL,
        Message NVARCHAR(MAX) NOT NULL,
        CreatedAt DATETIME2(7) NOT NULL DEFAULT GETUTCDATE(),
        
        -- Constraints
        CONSTRAINT CHK_EventLog_EventType_NotEmpty CHECK (LEN(TRIM(EventType)) > 0),
        CONSTRAINT CHK_EventLog_Message_NotEmpty CHECK (LEN(TRIM(Message)) > 0)
    );
    
    -- Indexes for event queries
    CREATE NONCLUSTERED INDEX IX_EventLog_EventType_CreatedAt ON dbo.EventLog (EventType, CreatedAt);
    CREATE NONCLUSTERED INDEX IX_EventLog_CreatedAt ON dbo.EventLog (CreatedAt);
    
    PRINT '✓ EventLog table created successfully';
    
    -- ============================================================================
    -- TABLE STATISTICS AND VALIDATION
    -- ============================================================================
    
    PRINT 'Validating table creation...';
    
    DECLARE @TableCount INT;
    SELECT @TableCount = COUNT(*)
    FROM INFORMATION_SCHEMA.TABLES 
    WHERE TABLE_SCHEMA = 'dbo' 
    AND TABLE_NAME IN (
        'AppDevices', 'PhoneNumbers', 'PhoneNumberDevices', 'VerificationFlows',
        'OtpRecords', 'FailedOtpAttempts', 'Memberships', 'AuthenticationContexts',
        'AuthenticationStates', 'LoginAttempts', 'MembershipAttempts', 'EventLog'
    );
    
    IF @TableCount = 12
        PRINT '✓ All 12 core domain tables created successfully';
    ELSE
    BEGIN
        DECLARE @ErrorMsg NVARCHAR(255) = 'Expected 12 tables, but found ' + CAST(@TableCount AS NVARCHAR(10));
        RAISERROR(@ErrorMsg, 16, 1);
    END
    
    -- Count total indexes created
    DECLARE @IndexCount INT;
    SELECT @IndexCount = COUNT(*)
    FROM sys.indexes i
    INNER JOIN sys.tables t ON i.object_id = t.object_id
    WHERE t.name IN (
        'AppDevices', 'PhoneNumbers', 'PhoneNumberDevices', 'VerificationFlows',
        'OtpRecords', 'FailedOtpAttempts', 'Memberships', 'AuthenticationContexts',
        'AuthenticationStates', 'LoginAttempts', 'MembershipAttempts', 'EventLog'
    )
    AND i.type > 0; -- Exclude heap indexes
    
    PRINT '✓ Created ' + CAST(@IndexCount AS NVARCHAR(10)) + ' indexes for optimal performance';
    
    COMMIT TRANSACTION;
    
    -- Log successful completion
    UPDATE dbo.DeploymentLog 
    SET Status = 'COMPLETED', EndTime = GETUTCDATE(), RowsAffected = @TableCount
    WHERE Id = @LogId;
    
    PRINT '';
    PRINT '================================================================================';
    PRINT 'Layer 2.1: Core Domain Tables Completed Successfully';
    PRINT 'Tables created: ' + CAST(@TableCount AS NVARCHAR(10));
    PRINT 'Indexes created: ' + CAST(@IndexCount AS NVARCHAR(10));
    PRINT 'Foreign key constraints: Ready for Layer 3';
    PRINT 'Next: Layer 3 - Relationships & Constraints';
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
    PRINT 'ERROR in Layer 2.1: ' + ERROR_MESSAGE();
    THROW;
END CATCH
GO