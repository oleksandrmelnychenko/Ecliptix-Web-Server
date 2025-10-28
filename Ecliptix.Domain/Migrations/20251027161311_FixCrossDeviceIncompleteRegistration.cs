using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class FixCrossDeviceIncompleteRegistration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships");

            migrationBuilder.DropIndex(
                name: "UQ_Memberships_ActiveMembership",
                table: "Memberships");

            migrationBuilder.CreateIndex(
                name: "UQ_Memberships_ActiveMembership",
                table: "Memberships",
                column: "MobileNumberId",
                unique: true,
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships",
                column: "MobileNumberId",
                filter: "IsDeleted = 0 AND Status = 'active'")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "CreationStatus" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships");

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_Login_Covering",
                table: "Memberships",
                column: "MobileNumberId",
                filter: "IsDeleted = 0 AND Status = 'active'")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "CreationStatus" });

            migrationBuilder.CreateIndex(
                name: "UQ_Memberships_ActiveMembership",
                table: "Memberships",
                columns: new[] { "MobileNumberId", "AppDeviceId", "IsDeleted" },
                unique: true);
        }
    }
}
