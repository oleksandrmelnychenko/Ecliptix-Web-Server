-- Ecliptix Authentication Context Procedures

BEGIN TRANSACTION;
GO

IF OBJECT_ID('dbo.CreateAuthenticationContext', 'P') IS NOT NULL DROP PROCEDURE dbo.CreateAuthenticationContext;
IF OBJECT_ID('dbo.ValidateAuthenticationContext', 'P') IS NOT NULL DROP PROCEDURE dbo.ValidateAuthenticationContext;
IF OBJECT_ID('dbo.RefreshAuthenticationContext', 'P') IS NOT NULL DROP PROCEDURE dbo.RefreshAuthenticationContext;
IF OBJECT_ID('dbo.InvalidateAuthenticationContext', 'P') IS NOT NULL DROP PROCEDURE dbo.InvalidateAuthenticationContext;
IF OBJECT_ID('dbo.InvalidateAllContextsForMobile', 'P') IS NOT NULL DROP PROCEDURE dbo.InvalidateAllContextsForMobile;
IF OBJECT_ID('dbo.CleanupExpiredContexts', 'P') IS NOT NULL DROP PROCEDURE dbo.CleanupExpiredContexts;
IF OBJECT_ID('dbo.UpdateAuthenticationState', 'P') IS NOT NULL DROP PROCEDURE dbo.UpdateAuthenticationState;
IF OBJECT_ID('dbo.GetAuthenticationState', 'P') IS NOT NULL DROP PROCEDURE dbo.GetAuthenticationState;
GO

CREATE PROCEDURE dbo.CreateAuthenticationContext
    @ContextToken VARBINARY(64),
    @MembershipId UNIQUEIDENTIFIER,
    @MobileNumberId UNIQUEIDENTIFIER,
    @ExpiresAt DATETIME2(7),
    @IpAddress NVARCHAR(45) = NULL,
    @UserAgent NVARCHAR(500) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @ContextId BIGINT;
    DECLARE @Success BIT = 1;
    DECLARE @Message NVARCHAR(255) = 'Authentication context created successfully';

    BEGIN TRY
        UPDATE dbo.AuthenticationContexts 
        SET IsActive = 0, 
            ContextState = 'invalidated',
            UpdatedAt = GETUTCDATE()
        WHERE MembershipId = @MembershipId 
          AND IsActive = 1 
          AND IsDeleted = 0;

        INSERT INTO dbo.AuthenticationContexts (
            ContextToken, MembershipId, MobileNumberId, ExpiresAt, 
            IpAddress, UserAgent, IsActive, ContextState
        )
        VALUES (
            @ContextToken, @MembershipId, @MobileNumberId, @ExpiresAt,
            @IpAddress, @UserAgent, 1, 'active'
        );

        SET @ContextId = SCOPE_IDENTITY();

        MERGE dbo.AuthenticationStates AS target
        USING (SELECT @MobileNumberId AS MobileNumberId) AS source
        ON target.MobileNumberId = source.MobileNumberId
        WHEN MATCHED THEN
            UPDATE SET 
                RecentAttempts = 0,
                WindowStartTime = GETUTCDATE(),
                LastAttemptTime = GETUTCDATE(),
                IsLocked = 0,
                LockedUntil = NULL,
                LastSyncTime = GETUTCDATE(),
                UpdatedAt = GETUTCDATE()
        WHEN NOT MATCHED THEN
            INSERT (MobileNumberId, RecentAttempts, WindowStartTime, LastAttemptTime, IsLocked, LastSyncTime)
            VALUES (@MobileNumberId, 0, GETUTCDATE(), GETUTCDATE(), 0, GETUTCDATE());

        SELECT @ContextId AS ContextId, @Success AS Success, @Message AS Message;

    END TRY
    BEGIN CATCH
        SET @Success = 0;
        SET @Message = ERROR_MESSAGE();
        SELECT NULL AS ContextId, @Success AS Success, @Message AS Message;
    END CATCH
END;
GO

CREATE PROCEDURE dbo.ValidateAuthenticationContext
    @ContextToken VARBINARY(64)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @ContextId BIGINT;
    DECLARE @MembershipId UNIQUEIDENTIFIER;
    DECLARE @MobileNumberId UNIQUEIDENTIFIER;
    DECLARE @ExpiresAt DATETIME2(7);
    DECLARE @ContextState NVARCHAR(20);
    DECLARE @IsValid BIT = 0;
    DECLARE @Message NVARCHAR(255);
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

    SELECT 
        @ContextId = Id,
        @MembershipId = MembershipId,
        @MobileNumberId = MobileNumberId,
        @ExpiresAt = ExpiresAt,
        @ContextState = ContextState
    FROM dbo.AuthenticationContexts
    WHERE ContextToken = @ContextToken
      AND IsActive = 1
      AND IsDeleted = 0;

    IF @ContextId IS NULL
    BEGIN
        SET @Message = 'Authentication context not found or inactive';
        SELECT @IsValid AS IsValid, @Message AS Message, 
               NULL AS ContextId, NULL AS MembershipId, NULL AS MobileNumberId;
        RETURN;
    END

    IF @CurrentTime >= @ExpiresAt
    BEGIN
        UPDATE dbo.AuthenticationContexts 
        SET ContextState = 'expired', 
            IsActive = 0,
            UpdatedAt = @CurrentTime
        WHERE Id = @ContextId;

        SET @Message = 'Authentication context has expired';
        SELECT @IsValid AS IsValid, @Message AS Message,
               NULL AS ContextId, NULL AS MembershipId, NULL AS MobileNumberId;
        RETURN;
    END

    IF @ContextState != 'active'
    BEGIN
        SET @Message = 'Authentication context is not active';
        SELECT @IsValid AS IsValid, @Message AS Message,
               NULL AS ContextId, NULL AS MembershipId, NULL AS MobileNumberId;
        RETURN;
    END

    UPDATE dbo.AuthenticationContexts 
    SET LastAccessedAt = @CurrentTime,
        UpdatedAt = @CurrentTime
    WHERE Id = @ContextId;

    SET @IsValid = 1;
    SET @Message = 'Authentication context is valid';
    
    SELECT @IsValid AS IsValid, @Message AS Message,
           @ContextId AS ContextId, @MembershipId AS MembershipId, @MobileNumberId AS MobileNumberId;
END;
GO

CREATE PROCEDURE dbo.RefreshAuthenticationContext
    @ContextToken VARBINARY(64),
    @NewExpiresAt DATETIME2(7)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @RowsAffected INT;
    DECLARE @Success BIT = 0;
    DECLARE @Message NVARCHAR(255);
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

    UPDATE dbo.AuthenticationContexts
    SET ExpiresAt = @NewExpiresAt,
        LastAccessedAt = @CurrentTime,
        UpdatedAt = @CurrentTime
    WHERE ContextToken = @ContextToken
      AND IsActive = 1
      AND IsDeleted = 0
      AND ContextState = 'active'
      AND ExpiresAt > @CurrentTime;

    SET @RowsAffected = @@ROWCOUNT;

    IF @RowsAffected > 0
    BEGIN
        SET @Success = 1;
        SET @Message = 'Authentication context refreshed successfully';
    END
    ELSE
    BEGIN
        SET @Message = 'Authentication context not found, expired, or inactive';
    END

    SELECT @Success AS Success, @Message AS Message;
END;
GO

CREATE PROCEDURE dbo.InvalidateAuthenticationContext
    @ContextToken VARBINARY(64)
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @RowsAffected INT;
    DECLARE @Success BIT = 0;
    DECLARE @Message NVARCHAR(255);
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

    UPDATE dbo.AuthenticationContexts
    SET IsActive = 0,
        ContextState = 'invalidated',
        UpdatedAt = @CurrentTime
    WHERE ContextToken = @ContextToken
      AND IsActive = 1
      AND IsDeleted = 0;

    SET @RowsAffected = @@ROWCOUNT;

    IF @RowsAffected > 0
    BEGIN
        SET @Success = 1;
        SET @Message = 'Authentication context invalidated successfully';
    END
    ELSE
    BEGIN
        SET @Message = 'Authentication context not found or already inactive';
    END

    SELECT @Success AS Success, @Message AS Message;
END;
GO

CREATE PROCEDURE dbo.InvalidateAllContextsForMobile
    @MobileNumberId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @ContextsInvalidated INT;
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

    UPDATE dbo.AuthenticationContexts
    SET IsActive = 0,
        ContextState = 'invalidated',
        UpdatedAt = @CurrentTime
    WHERE MobileNumberId = @MobileNumberId
      AND IsActive = 1
      AND IsDeleted = 0;

    SET @ContextsInvalidated = @@ROWCOUNT;

    SELECT 1 AS Success, 
           @ContextsInvalidated AS ContextsInvalidated,
           'All authentication contexts invalidated successfully' AS Message;
END;
GO

CREATE PROCEDURE dbo.CleanupExpiredContexts
    @BatchSize INT = 1000,
    @OlderThanHours INT = 24
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @CutoffTime DATETIME2(7) = DATEADD(hour, -@OlderThanHours, GETUTCDATE());
    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();
    DECLARE @TotalCleaned INT = 0;
    DECLARE @BatchCleaned INT = 1;

    UPDATE TOP (@BatchSize) dbo.AuthenticationContexts
    SET ContextState = 'expired',
        IsActive = 0,
        UpdatedAt = @CurrentTime
    WHERE ExpiresAt < @CurrentTime
      AND IsActive = 1
      AND IsDeleted = 0;

    SET @BatchCleaned = @@ROWCOUNT;
    SET @TotalCleaned = @TotalCleaned + @BatchCleaned;

    UPDATE TOP (@BatchSize) dbo.AuthenticationContexts
    SET IsDeleted = 1,
        UpdatedAt = @CurrentTime
    WHERE ExpiresAt < @CutoffTime
      AND IsDeleted = 0;

    SET @BatchCleaned = @@ROWCOUNT;
    SET @TotalCleaned = @TotalCleaned + @BatchCleaned;

    SELECT @TotalCleaned AS TotalCleaned, 
           'Cleanup completed successfully' AS Message;
END;
GO

CREATE PROCEDURE dbo.UpdateAuthenticationState
    @MobileNumberId UNIQUEIDENTIFIER,
    @RecentAttempts INT,
    @WindowStartTime DATETIME2(7),
    @IsLocked BIT = 0,
    @LockedUntil DATETIME2(7) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @CurrentTime DATETIME2(7) = GETUTCDATE();

    MERGE dbo.AuthenticationStates AS target
    USING (SELECT @MobileNumberId AS MobileNumberId) AS source
    ON target.MobileNumberId = source.MobileNumberId
    WHEN MATCHED THEN
        UPDATE SET 
            RecentAttempts = @RecentAttempts,
            WindowStartTime = @WindowStartTime,
            LastAttemptTime = @CurrentTime,
            IsLocked = @IsLocked,
            LockedUntil = @LockedUntil,
            LastSyncTime = @CurrentTime,
            UpdatedAt = @CurrentTime
    WHEN NOT MATCHED THEN
        INSERT (MobileNumberId, RecentAttempts, WindowStartTime, LastAttemptTime, 
                IsLocked, LockedUntil, LastSyncTime)
        VALUES (@MobileNumberId, @RecentAttempts, @WindowStartTime, @CurrentTime,
                @IsLocked, @LockedUntil, @CurrentTime);

    SELECT 1 AS Success, 'Authentication state updated successfully' AS Message;
END;
GO

CREATE PROCEDURE dbo.GetAuthenticationState
    @MobileNumberId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
        MobileNumberId,
        RecentAttempts,
        WindowStartTime,
        LastAttemptTime,
        IsLocked,
        LockedUntil,
        LastSyncTime,
        CreatedAt,
        UpdatedAt
    FROM dbo.AuthenticationStates
    WHERE MobileNumberId = @MobileNumberId;

    IF @@ROWCOUNT = 0
    BEGIN
        SELECT 
            @MobileNumberId AS MobileNumberId,
            0 AS RecentAttempts,
            GETUTCDATE() AS WindowStartTime,
            NULL AS LastAttemptTime,
            0 AS IsLocked,
            NULL AS LockedUntil,
            GETUTCDATE() AS LastSyncTime,
            GETUTCDATE() AS CreatedAt,
            GETUTCDATE() AS UpdatedAt;
    END
END;
GO

COMMIT TRANSACTION;
GO

PRINT 'Authentication Context procedures created successfully.';
GO