using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class ChangeDeviceForeignKeysToUseDeviceId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AccountPinAuth_Devices",
                table: "AccountPinAuth");

            migrationBuilder.DropForeignKey(
                name: "FK_DeviceContexts_Devices",
                table: "DeviceContexts");

            migrationBuilder.DropForeignKey(
                name: "FK_LoginAttempts_Devices",
                table: "LoginAttempts");

            migrationBuilder.DropForeignKey(
                name: "FK_Memberships_Devices",
                table: "Memberships");

            migrationBuilder.DropForeignKey(
                name: "FK_VerificationFlows_Devices",
                table: "VerificationFlows");

            migrationBuilder.DropForeignKey(
                name: "FK_VerificationLogs_Devices",
                table: "VerificationLogs");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_Devices_UniqueId",
                table: "Devices");

            migrationBuilder.AddUniqueConstraint(
                name: "AK_Devices_DeviceId",
                table: "Devices",
                column: "DeviceId");

            migrationBuilder.AddForeignKey(
                name: "FK_AccountPinAuth_Devices",
                table: "AccountPinAuth",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "DeviceId");

            migrationBuilder.AddForeignKey(
                name: "FK_DeviceContexts_Devices",
                table: "DeviceContexts",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "DeviceId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_LoginAttempts_Devices",
                table: "LoginAttempts",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "DeviceId");

            migrationBuilder.AddForeignKey(
                name: "FK_Memberships_Devices",
                table: "Memberships",
                column: "AppDeviceId",
                principalTable: "Devices",
                principalColumn: "DeviceId");

            migrationBuilder.AddForeignKey(
                name: "FK_VerificationFlows_Devices",
                table: "VerificationFlows",
                column: "AppDeviceId",
                principalTable: "Devices",
                principalColumn: "DeviceId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_VerificationLogs_Devices",
                table: "VerificationLogs",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "DeviceId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AccountPinAuth_Devices",
                table: "AccountPinAuth");

            migrationBuilder.DropForeignKey(
                name: "FK_DeviceContexts_Devices",
                table: "DeviceContexts");

            migrationBuilder.DropForeignKey(
                name: "FK_LoginAttempts_Devices",
                table: "LoginAttempts");

            migrationBuilder.DropForeignKey(
                name: "FK_Memberships_Devices",
                table: "Memberships");

            migrationBuilder.DropForeignKey(
                name: "FK_VerificationFlows_Devices",
                table: "VerificationFlows");

            migrationBuilder.DropForeignKey(
                name: "FK_VerificationLogs_Devices",
                table: "VerificationLogs");

            migrationBuilder.DropUniqueConstraint(
                name: "AK_Devices_DeviceId",
                table: "Devices");

            migrationBuilder.AddUniqueConstraint(
                name: "AK_Devices_UniqueId",
                table: "Devices",
                column: "UniqueId");

            migrationBuilder.AddForeignKey(
                name: "FK_AccountPinAuth_Devices",
                table: "AccountPinAuth",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId");

            migrationBuilder.AddForeignKey(
                name: "FK_DeviceContexts_Devices",
                table: "DeviceContexts",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_LoginAttempts_Devices",
                table: "LoginAttempts",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId");

            migrationBuilder.AddForeignKey(
                name: "FK_Memberships_Devices",
                table: "Memberships",
                column: "AppDeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId");

            migrationBuilder.AddForeignKey(
                name: "FK_VerificationFlows_Devices",
                table: "VerificationFlows",
                column: "AppDeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_VerificationLogs_Devices",
                table: "VerificationLogs",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId");
        }
    }
}
