using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    public partial class RemoveLogoutAuditDeviceFKAndCleanupDuplicates : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_LogoutAudits_Devices",
                table: "LogoutAudits");

            migrationBuilder.DropIndex(
                name: "IX_Devices_AppInstanceId",
                table: "Devices");

            migrationBuilder.Sql(@"
                WITH DeviceCTE AS (
                    SELECT
                        UniqueId,
                        AppInstanceId,
                        ROW_NUMBER() OVER (PARTITION BY AppInstanceId ORDER BY CreatedAt DESC, Id DESC) AS RowNum
                    FROM Devices
                    WHERE IsDeleted = 0
                )
                UPDATE Devices
                SET IsDeleted = 1, DeletedAt = SYSDATETIMEOFFSET()
                WHERE UniqueId IN (
                    SELECT UniqueId
                    FROM DeviceCTE
                    WHERE RowNum > 1
                );
            ");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_AppInstanceId",
                table: "Devices",
                column: "AppInstanceId",
                unique: true,
                filter: "IsDeleted = 0");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Devices_AppInstanceId",
                table: "Devices");

            migrationBuilder.CreateIndex(
                name: "IX_Devices_AppInstanceId",
                table: "Devices",
                column: "AppInstanceId");

            migrationBuilder.AddForeignKey(
                name: "FK_LogoutAudits_Devices",
                table: "LogoutAudits",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "UniqueId");
        }
    }
}
