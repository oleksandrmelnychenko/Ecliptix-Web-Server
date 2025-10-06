using System.Data.Common;
using Akka.Actor;
using Ecliptix.Domain.Memberships.ActorEvents;
using Ecliptix.Domain.Memberships.Failures;
using Ecliptix.Domain.Memberships.Persistors.CompiledQueries;
using Ecliptix.Domain.Memberships.Persistors.QueryRecords;
using Ecliptix.Domain.Memberships.Persistors.QueryResults;
using Ecliptix.Memberships.Persistor.Schema;
using Ecliptix.Memberships.Persistor.Schema.Entities;
using Ecliptix.Utilities;
using Ecliptix.Protobuf.Membership;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Serilog;

namespace Ecliptix.Domain.Memberships.Persistors;

public class VerificationFlowPersistorActor : PersistorBase<VerificationFlowFailure>
{
    public VerificationFlowPersistorActor(
        IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
        : base(dbContextFactory)
    {
        Become(Ready);
    }

    public static Props Build(IDbContextFactory<EcliptixSchemaContext> dbContextFactory)
    {
        return Props.Create(() => new VerificationFlowPersistorActor(dbContextFactory));
    }

    private void Ready()
    {
        Receive<InitiateFlowAndReturnStateActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => InitiateFlowAsync(ctx, actorEvent), "InitiateVerificationFlow")
                .PipeTo(Sender));
        Receive<RequestResendOtpActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => RequestResendOtpAsync(ctx, actorEvent), "RequestResendOtp").PipeTo(Sender));
        Receive<UpdateVerificationFlowStatusActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => UpdateVerificationFlowStatusAsync(ctx, actorEvent),
                    "UpdateVerificationFlowStatus")
                .PipeTo(Sender));
        Receive<EnsureMobileNumberActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => EnsureMobileNumberAsync(ctx, actorEvent), "EnsureMobileNumber")
                .PipeTo(Sender));
        Receive<VerifyMobileForSecretKeyRecoveryActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => VerifyMobileForSecretKeyRecoveryAsync(ctx, actorEvent),
                    "VerifyMobileForSecretKeyRecovery")
                .PipeTo(Sender));
        Receive<GetMobileNumberActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => GetMobileNumberAsync(ctx, actorEvent), "GetMobileNumber").PipeTo(Sender));
        Receive<CreateOtpActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => CreateOtpAsync(ctx, actorEvent), "CreateOtp").PipeTo(Sender));
        Receive<UpdateOtpStatusActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => UpdateOtpStatusAsync(ctx, actorEvent), "UpdateOtpStatus").PipeTo(Sender));
        Receive<ExpireAssociatedOtpActorEvent>(actorEvent =>
            ExecuteWithContext(ctx => ExpireAssociatedOtpAsync(ctx, actorEvent), "ExpireAssociatedOtp")
                .PipeTo(Sender));
    }

    private static async Task<Result<VerificationFlowQueryRecord, VerificationFlowFailure>> InitiateFlowAsync(
        EcliptixSchemaContext ctx, InitiateFlowAndReturnStateActorEvent cmd)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync();

        try
        {
            Ecliptix.Memberships.Persistor.Schema.Entities.MobileNumber? mobile = await MobileNumberQueries.GetByUniqueId(ctx, cmd.MobileNumberUniqueId);
            if (mobile == null)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("mobile_number_not_found"));
            }

            bool deviceExists = await DeviceQueries.ExistsByUniqueId(ctx, cmd.AppDeviceId);
            if (!deviceExists)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("device_not_found"));
            }

            Ecliptix.Memberships.Persistor.Schema.Entities.VerificationFlow? existingActiveFlow = await VerificationFlowQueries.GetActiveFlowForRecovery(
                ctx, cmd.MobileNumberUniqueId, cmd.AppDeviceId,
                ConvertPurposeToString(cmd.Purpose));

            if (existingActiveFlow != null)
            {
                await ctx.VerificationFlows
                    .Where(vf => vf.Id == existingActiveFlow.Id)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(vf => vf.ConnectionId, (long?)cmd.ConnectId)
                        .SetProperty(vf => vf.UpdatedAt, DateTime.UtcNow));

                await ctx.OtpCodes
                    .Where(o => o.VerificationFlowId == existingActiveFlow.Id &&
                                o.Status == "active" &&
                                !o.IsDeleted)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(o => o.Status, "expired")
                        .SetProperty(o => o.UpdatedAt, DateTime.UtcNow));

                await transaction.CommitAsync();

                existingActiveFlow.ConnectionId = cmd.ConnectId;
                existingActiveFlow.UpdatedAt = DateTime.UtcNow;
                existingActiveFlow.MobileNumber = mobile;
                existingActiveFlow.OtpCodes = new List<Ecliptix.Memberships.Persistor.Schema.Entities.OtpCode>();

                return MapToVerificationFlowRecord(existingActiveFlow);
            }

            int mobileFlowCount = await VerificationFlowQueries.CountRecentByMobileId(
                ctx, mobile.Id, DateTime.UtcNow.AddHours(-1));
            if (mobileFlowCount >= 30)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded("rate_limit_exceeded"));
            }

            int deviceFlowCount = await VerificationFlowQueries.CountRecentByDevice(
                ctx, cmd.AppDeviceId, DateTime.UtcNow.AddHours(-1));
            if (deviceFlowCount >= 10)
            {
                await transaction.RollbackAsync();
                return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.RateLimitExceeded("device_rate_limit_exceeded"));
            }

            Ecliptix.Memberships.Persistor.Schema.Entities.VerificationFlow flow = new VerificationFlow
            {
                UniqueId = Guid.NewGuid(),
                MobileNumberId = mobile.Id,
                AppDeviceId = cmd.AppDeviceId,
                Purpose = ConvertPurposeToString(cmd.Purpose),
                Status = "pending",
                ExpiresAt = DateTime.UtcNow.AddMinutes(15),
                ConnectionId = cmd.ConnectId,
                OtpCount = 0,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsDeleted = false
            };

            ctx.VerificationFlows.Add(flow);
            await ctx.SaveChangesAsync();

            await transaction.CommitAsync();

            Ecliptix.Memberships.Persistor.Schema.Entities.VerificationFlow? flowWithOtp = await VerificationFlowQueries.GetByUniqueIdWithActiveOtp(ctx, flow.UniqueId);
            return MapToVerificationFlowRecord(flowWithOtp!);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Generic($"Initiate flow failed: {ex.Message}", ex));
        }
    }

    private static async Task<Result<string, VerificationFlowFailure>> RequestResendOtpAsync(
        EcliptixSchemaContext ctx, RequestResendOtpActorEvent cmd)
    {
        try
        {
            Ecliptix.Memberships.Persistor.Schema.Entities.VerificationFlow? flow = await VerificationFlowQueries.GetByUniqueId(ctx, cmd.FlowUniqueId);
            if (flow == null)
                return Result<string, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Flow not found"));

            return Result<string, VerificationFlowFailure>.Ok("resend_allowed");
        }
        catch (Exception ex)
        {
            return Result<string, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Request resend failed: {ex.Message}"));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> UpdateOtpStatusAsync(
        EcliptixSchemaContext ctx, UpdateOtpStatusActorEvent cmd)
    {
        try
        {
            int rowsAffected = await ctx.OtpCodes
                .Where(o => o.UniqueId == cmd.OtpIdentified && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, ConvertVerificationFlowStatusToOtpStatus(cmd.Status))
                    .SetProperty(o => o.UpdatedAt, DateTime.UtcNow));

            if (rowsAffected == 0)
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("OTP not found"));

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update OTP status failed: {ex.Message}"));
        }
    }

    private async Task<Result<MobileNumberQueryRecord, VerificationFlowFailure>> GetMobileNumberAsync(
        EcliptixSchemaContext ctx, GetMobileNumberActorEvent cmd)
    {
        try
        {
            Ecliptix.Memberships.Persistor.Schema.Entities.MobileNumber? mobile = await MobileNumberQueries.GetByUniqueId(ctx, cmd.MobileNumberIdentifier);
            if (mobile == null)
                return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound(VerificationFlowMessageKeys.MobileNotFound));

            return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Ok(new MobileNumberQueryRecord
            {
                MobileNumber = mobile.Number,
                Region = mobile.Region,
                UniqueId = mobile.UniqueId
            });
        }
        catch (Exception ex)
        {
            return Result<MobileNumberQueryRecord, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Get mobile failed: {ex.Message}"));
        }
    }

    private async Task<Result<int, VerificationFlowFailure>> UpdateVerificationFlowStatusAsync(
        EcliptixSchemaContext ctx, UpdateVerificationFlowStatusActorEvent cmd)
    {
        try
        {
            int rowsAffected = await ctx.VerificationFlows
                .Where(f => f.UniqueId == cmd.FlowIdentifier && !f.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(f => f.Status, cmd.Status.ToString().ToLowerInvariant())
                    .SetProperty(f => f.UpdatedAt, DateTime.UtcNow));

            if (rowsAffected == 0)
                return Result<int, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Flow not found"));

            return Result<int, VerificationFlowFailure>.Ok(rowsAffected);
        }
        catch (Exception ex)
        {
            return Result<int, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Update flow status failed: {ex.Message}"));
        }
    }

    private static async Task<Result<CreateOtpResult, VerificationFlowFailure>> CreateOtpAsync(
        EcliptixSchemaContext ctx, CreateOtpActorEvent cmd)
    {
        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync();

        try
        {
            Ecliptix.Memberships.Persistor.Schema.Entities.VerificationFlow? flow = await VerificationFlowQueries.GetByUniqueId(ctx, cmd.OtpRecord.FlowUniqueId);
            if (flow == null || flow.ExpiresAt <= DateTime.UtcNow)
            {
                await transaction.RollbackAsync();
                return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("flow_not_found_or_invalid"));
            }

            if (flow.OtpCount >= 5)
            {
                await transaction.RollbackAsync();
                return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.OtpMaxAttemptsReached("max_otp_attempts_reached"));
            }

            await ctx.OtpCodes
                .Where(o => o.VerificationFlowId == flow.Id && o.Status == "active" && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "expired")
                    .SetProperty(o => o.UpdatedAt, DateTime.UtcNow));

            Ecliptix.Memberships.Persistor.Schema.Entities.OtpCode otp = new OtpCode
            {
                UniqueId = Guid.NewGuid(),
                VerificationFlowId = flow.Id,
                OtpValue = cmd.OtpRecord.OtpHash,
                OtpSalt = cmd.OtpRecord.OtpSalt,
                Status = ConvertVerificationFlowStatusToOtpStatus(cmd.OtpRecord.Status),
                ExpiresAt = cmd.OtpRecord.ExpiresAt,
                AttemptCount = 0,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsDeleted = false
            };

            ctx.OtpCodes.Add(otp);

            await ctx.VerificationFlows
                .Where(f => f.Id == flow.Id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(f => f.OtpCount, f => f.OtpCount + 1)
                    .SetProperty(f => f.UpdatedAt, DateTime.UtcNow));

            await ctx.SaveChangesAsync();

            await transaction.CommitAsync();

            return Result<CreateOtpResult, VerificationFlowFailure>.Ok(new CreateOtpResult
            {
                OtpUniqueId = otp.UniqueId,
                Outcome = "created"
            });
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<CreateOtpResult, VerificationFlowFailure>.Err(
                VerificationFlowFailure.OtpGenerationFailed($"Create OTP failed: {ex.Message}"));
        }
    }

    private async Task<Result<Guid, VerificationFlowFailure>> EnsureMobileNumberAsync(
        EcliptixSchemaContext ctx, EnsureMobileNumberActorEvent cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd.MobileNumber))
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.Validation("invalid_mobile_number"));

        await using Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction = await ctx.Database.BeginTransactionAsync();

        try
        {
            Ecliptix.Memberships.Persistor.Schema.Entities.MobileNumber? existing = await MobileNumberQueries.GetByNumberAndRegion(
                ctx, cmd.MobileNumber, cmd.RegionCode);

            if (existing != null)
            {
                await transaction.CommitAsync();
                return Result<Guid, VerificationFlowFailure>.Ok(existing.UniqueId);
            }

            Ecliptix.Memberships.Persistor.Schema.Entities.MobileNumber mobile = new MobileNumber
            {
                UniqueId = Guid.NewGuid(),
                Number = cmd.MobileNumber,
                Region = cmd.RegionCode,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                IsDeleted = false
            };

            ctx.MobileNumbers.Add(mobile);
            await ctx.SaveChangesAsync();

            await transaction.CommitAsync();

            return Result<Guid, VerificationFlowFailure>.Ok(mobile.UniqueId);
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync();
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Ensure mobile failed: {ex.Message}", ex));
        }
    }

    private static async Task<Result<Guid, VerificationFlowFailure>> VerifyMobileForSecretKeyRecoveryAsync(
        EcliptixSchemaContext ctx, VerifyMobileForSecretKeyRecoveryActorEvent cmd)
    {
        try
        {
            Ecliptix.Memberships.Persistor.Schema.Entities.MobileNumber? mobile = await MobileNumberQueries.GetByNumberAndRegion(
                ctx, cmd.MobileNumber, cmd.RegionCode);

            if (mobile == null)
                return Result<Guid, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.Validation("mobile_not_found"));

            return Result<Guid, VerificationFlowFailure>.Ok(mobile.UniqueId);
        }
        catch (Exception ex)
        {
            return Result<Guid, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Verify mobile recovery failed: {ex.Message}", ex));
        }
    }

    private async Task<Result<Unit, VerificationFlowFailure>> ExpireAssociatedOtpAsync(
        EcliptixSchemaContext ctx, ExpireAssociatedOtpActorEvent cmd)
    {
        try
        {
            Ecliptix.Memberships.Persistor.Schema.Entities.VerificationFlow? flow = await VerificationFlowQueries.GetByUniqueId(ctx, cmd.FlowUniqueId);
            if (flow == null)
                return Result<Unit, VerificationFlowFailure>.Err(
                    VerificationFlowFailure.NotFound("Flow not found"));

            await ctx.OtpCodes
                .Where(o => o.VerificationFlowId == flow.Id && o.Status == "active" && !o.IsDeleted)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(o => o.Status, "expired")
                    .SetProperty(o => o.UpdatedAt, DateTime.UtcNow));

            return Result<Unit, VerificationFlowFailure>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            return Result<Unit, VerificationFlowFailure>.Err(
                VerificationFlowFailure.PersistorAccess($"Expire OTP failed: {ex.Message}"));
        }
    }

    private static Result<VerificationFlowQueryRecord, VerificationFlowFailure> MapToVerificationFlowRecord(
        VerificationFlow flow)
    {
        Ecliptix.Memberships.Persistor.Schema.Entities.OtpCode? activeOtp = flow.OtpCodes?.FirstOrDefault(o => o.Status == "active" && !o.IsDeleted);
        Option<OtpQueryRecord> otpActive = activeOtp != null
            ? Option<OtpQueryRecord>.Some(new OtpQueryRecord
            {
                UniqueIdentifier = activeOtp.UniqueId,
                FlowUniqueId = flow.UniqueId,
                MobileNumberIdentifier = flow.MobileNumber?.UniqueId ?? Guid.Empty,
                OtpHash = activeOtp.OtpValue,
                OtpSalt = activeOtp.OtpSalt,
                ExpiresAt = activeOtp.ExpiresAt,
                Status = Enum.Parse<VerificationFlowStatus>(activeOtp.Status, true),
                IsActive = activeOtp.Status == "active"
            })
            : Option<OtpQueryRecord>.None;

        VerificationFlowQueryRecord flowRecord = new()
        {
            UniqueIdentifier = flow.UniqueId,
            MobileNumberIdentifier = flow.MobileNumber?.UniqueId ?? Guid.Empty,
            AppDeviceIdentifier = flow.AppDeviceId,
            ConnectId = (uint?)flow.ConnectionId,
            ExpiresAt = flow.ExpiresAt,
            Status = Enum.Parse<VerificationFlowStatus>(flow.Status, true),
            Purpose = Enum.Parse<VerificationPurpose>(flow.Purpose, true),
            OtpCount = flow.OtpCount,
            OtpActive = otpActive.HasValue ? otpActive.Value : null
        };

        return Result<VerificationFlowQueryRecord, VerificationFlowFailure>.Ok(flowRecord);
    }

    private static string ConvertPurposeToString(VerificationPurpose purpose)
    {
        return purpose switch
        {
            VerificationPurpose.Registration => "registration",
            VerificationPurpose.Login => "login",
            VerificationPurpose.PasswordRecovery => "password_recovery",
            _ => "unspecified"
        };
    }

    private static string ConvertVerificationFlowStatusToOtpStatus(VerificationFlowStatus status)
    {
        return status switch
        {
            VerificationFlowStatus.Pending => "active",
            VerificationFlowStatus.Verified => "used",
            VerificationFlowStatus.Failed => "invalid",
            VerificationFlowStatus.Expired => "expired",
            VerificationFlowStatus.MaxAttemptsReached => "invalid",
            _ => "expired"
        };
    }

    protected override VerificationFlowFailure MapDbException(DbException ex)
    {
        if (ex is SqlException sqlEx)
        {
            return sqlEx.Number switch
            {
                2627 or 2601 => VerificationFlowFailure.ConcurrencyConflict($"Unique constraint violation: {sqlEx.Message}"),
                547 => VerificationFlowFailure.Validation($"Foreign key constraint violation: {sqlEx.Message}"),
                1205 => VerificationFlowFailure.ConcurrencyConflict($"Deadlock detected: {sqlEx.Message}"),
                -2 => VerificationFlowFailure.PersistorAccess("Command timeout occurred", sqlEx),
                2 => VerificationFlowFailure.PersistorAccess("Network error occurred", sqlEx),
                18456 => VerificationFlowFailure.PersistorAccess("Authentication failed", sqlEx),
                _ => VerificationFlowFailure.PersistorAccess($"Database error (Code: {sqlEx.Number}): {sqlEx.Message}", sqlEx)
            };
        }

        return VerificationFlowFailure.PersistorAccess("Database operation failed", ex);
    }

    protected override VerificationFlowFailure CreateTimeoutFailure(TimeoutException ex)
    {
        return VerificationFlowFailure.PersistorAccess("Database operation timed out", ex);
    }

    protected override VerificationFlowFailure CreateGenericFailure(Exception ex)
    {
        return VerificationFlowFailure.Generic($"Unexpected error in verification flow persistor: {ex.Message}", ex);
    }

    protected override SupervisorStrategy SupervisorStrategy()
    {
        return PersistorSupervisorStrategy.CreateStrategy();
    }
}