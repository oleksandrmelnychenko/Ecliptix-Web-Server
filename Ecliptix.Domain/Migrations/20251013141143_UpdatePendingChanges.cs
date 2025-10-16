using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class UpdatePendingChanges : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameIndex(
                name: "UQ_VerificationFlow_UniqueId",
                table: "VerificationFlows",
                newName: "UQ_VerificationFlowEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_VerificationFlow_UpdatedAt",
                table: "VerificationFlows",
                newName: "IX_VerificationFlowEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_VerificationFlow_CreatedAt",
                table: "VerificationFlows",
                newName: "IX_VerificationFlowEntity_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_OtpCode_UniqueId",
                table: "OtpCodes",
                newName: "UQ_OtpCodeEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_OtpCode_UpdatedAt",
                table: "OtpCodes",
                newName: "IX_OtpCodeEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_OtpCode_CreatedAt",
                table: "OtpCodes",
                newName: "IX_OtpCodeEntity_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_MobileNumber_UniqueId",
                table: "MobileNumbers",
                newName: "UQ_MobileNumberEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_MobileNumber_UpdatedAt",
                table: "MobileNumbers",
                newName: "IX_MobileNumberEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_MobileDevice_UniqueId",
                table: "MobileDevices",
                newName: "UQ_MobileDeviceEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_MobileDevice_UpdatedAt",
                table: "MobileDevices",
                newName: "IX_MobileDeviceEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_MobileDevice_CreatedAt",
                table: "MobileDevices",
                newName: "IX_MobileDeviceEntity_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_Membership_UpdatedAt",
                table: "Memberships",
                newName: "IX_MembershipEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_Membership_CreatedAt",
                table: "Memberships",
                newName: "IX_MembershipEntity_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_MasterKeyShare_UniqueId",
                table: "MasterKeyShares",
                newName: "UQ_MasterKeyShareEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_MasterKeyShare_UpdatedAt",
                table: "MasterKeyShares",
                newName: "IX_MasterKeyShareEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_MasterKeyShare_CreatedAt",
                table: "MasterKeyShares",
                newName: "IX_MasterKeyShareEntity_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_LogoutAudit_UniqueId",
                table: "LogoutAudits",
                newName: "UQ_LogoutAuditEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_LogoutAudit_UpdatedAt",
                table: "LogoutAudits",
                newName: "IX_LogoutAuditEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_LogoutAudit_CreatedAt",
                table: "LogoutAudits",
                newName: "IX_LogoutAuditEntity_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_LoginAttempt_UniqueId",
                table: "LoginAttempts",
                newName: "UQ_LoginAttemptEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_LoginAttempt_UpdatedAt",
                table: "LoginAttempts",
                newName: "IX_LoginAttemptEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_LoginAttempt_CreatedAt",
                table: "LoginAttempts",
                newName: "IX_LoginAttemptEntity_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_FailedOtpAttempt_UniqueId",
                table: "FailedOtpAttempts",
                newName: "UQ_FailedOtpAttemptEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_FailedOtpAttempt_UpdatedAt",
                table: "FailedOtpAttempts",
                newName: "IX_FailedOtpAttemptEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_FailedOtpAttempt_CreatedAt",
                table: "FailedOtpAttempts",
                newName: "IX_FailedOtpAttemptEntity_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_Device_UniqueId",
                table: "Devices",
                newName: "UQ_DeviceEntity_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_Device_UpdatedAt",
                table: "Devices",
                newName: "IX_DeviceEntity_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_Device_CreatedAt",
                table: "Devices",
                newName: "IX_DeviceEntity_CreatedAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameIndex(
                name: "UQ_VerificationFlowEntity_UniqueId",
                table: "VerificationFlows",
                newName: "UQ_VerificationFlow_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_VerificationFlowEntity_UpdatedAt",
                table: "VerificationFlows",
                newName: "IX_VerificationFlow_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_VerificationFlowEntity_CreatedAt",
                table: "VerificationFlows",
                newName: "IX_VerificationFlow_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_OtpCodeEntity_UniqueId",
                table: "OtpCodes",
                newName: "UQ_OtpCode_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_OtpCodeEntity_UpdatedAt",
                table: "OtpCodes",
                newName: "IX_OtpCode_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_OtpCodeEntity_CreatedAt",
                table: "OtpCodes",
                newName: "IX_OtpCode_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_MobileNumberEntity_UniqueId",
                table: "MobileNumbers",
                newName: "UQ_MobileNumber_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_MobileNumberEntity_UpdatedAt",
                table: "MobileNumbers",
                newName: "IX_MobileNumber_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_MobileDeviceEntity_UniqueId",
                table: "MobileDevices",
                newName: "UQ_MobileDevice_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_MobileDeviceEntity_UpdatedAt",
                table: "MobileDevices",
                newName: "IX_MobileDevice_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_MobileDeviceEntity_CreatedAt",
                table: "MobileDevices",
                newName: "IX_MobileDevice_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_MembershipEntity_UpdatedAt",
                table: "Memberships",
                newName: "IX_Membership_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_MembershipEntity_CreatedAt",
                table: "Memberships",
                newName: "IX_Membership_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_MasterKeyShareEntity_UniqueId",
                table: "MasterKeyShares",
                newName: "UQ_MasterKeyShare_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_MasterKeyShareEntity_UpdatedAt",
                table: "MasterKeyShares",
                newName: "IX_MasterKeyShare_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_MasterKeyShareEntity_CreatedAt",
                table: "MasterKeyShares",
                newName: "IX_MasterKeyShare_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_LogoutAuditEntity_UniqueId",
                table: "LogoutAudits",
                newName: "UQ_LogoutAudit_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_LogoutAuditEntity_UpdatedAt",
                table: "LogoutAudits",
                newName: "IX_LogoutAudit_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_LogoutAuditEntity_CreatedAt",
                table: "LogoutAudits",
                newName: "IX_LogoutAudit_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_LoginAttemptEntity_UniqueId",
                table: "LoginAttempts",
                newName: "UQ_LoginAttempt_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_LoginAttemptEntity_UpdatedAt",
                table: "LoginAttempts",
                newName: "IX_LoginAttempt_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_LoginAttemptEntity_CreatedAt",
                table: "LoginAttempts",
                newName: "IX_LoginAttempt_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_FailedOtpAttemptEntity_UniqueId",
                table: "FailedOtpAttempts",
                newName: "UQ_FailedOtpAttempt_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_FailedOtpAttemptEntity_UpdatedAt",
                table: "FailedOtpAttempts",
                newName: "IX_FailedOtpAttempt_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_FailedOtpAttemptEntity_CreatedAt",
                table: "FailedOtpAttempts",
                newName: "IX_FailedOtpAttempt_CreatedAt");

            migrationBuilder.RenameIndex(
                name: "UQ_DeviceEntity_UniqueId",
                table: "Devices",
                newName: "UQ_Device_UniqueId");

            migrationBuilder.RenameIndex(
                name: "IX_DeviceEntity_UpdatedAt",
                table: "Devices",
                newName: "IX_Device_UpdatedAt");

            migrationBuilder.RenameIndex(
                name: "IX_DeviceEntity_CreatedAt",
                table: "Devices",
                newName: "IX_Device_CreatedAt");
        }
    }
}
