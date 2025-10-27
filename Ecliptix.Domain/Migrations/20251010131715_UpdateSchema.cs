using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    public partial class UpdateSchema : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Memberships_MobileNumberId",
                table: "Memberships");

            migrationBuilder.CreateIndex(
                name: "UQ_MobileNumbers_Number",
                table: "MobileNumbers",
                column: "Number",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_MobileNumberId",
                table: "Memberships",
                column: "MobileNumberId",
                unique: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "UQ_MobileNumbers_Number",
                table: "MobileNumbers");

            migrationBuilder.DropIndex(
                name: "IX_Memberships_MobileNumberId",
                table: "Memberships");

            migrationBuilder.CreateIndex(
                name: "IX_Memberships_MobileNumberId",
                table: "Memberships",
                column: "MobileNumberId");
        }
    }
}
