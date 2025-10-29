using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class AddIndexOnVerificationLogsDeviceId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_VerificationLogs_DeviceId",
                table: "VerificationLogs");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_DeviceId",
                table: "VerificationLogs",
                column: "DeviceId",
                filter: "IsDeleted = 0");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_VerificationLogs_DeviceId",
                table: "VerificationLogs");

            migrationBuilder.CreateIndex(
                name: "IX_VerificationLogs_DeviceId",
                table: "VerificationLogs",
                column: "DeviceId");
        }
    }
}
