using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class ImproveAccountProfileIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AccountProfiles_AccountId",
                table: "AccountProfiles");

            migrationBuilder.DropIndex(
                name: "IX_AccountProfiles_ProfileName_Unique",
                table: "AccountProfiles");

            migrationBuilder.CreateIndex(
                name: "IX_AccountProfiles_AccountId_Unique",
                table: "AccountProfiles",
                column: "AccountId",
                unique: true,
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_AccountProfiles_ProfileName_Covering",
                table: "AccountProfiles",
                column: "ProfileName",
                unique: true,
                filter: "IsDeleted = 0")
                .Annotation("SqlServer:Include", new[] { "AccountId", "DisplayName" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AccountProfiles_AccountId_Unique",
                table: "AccountProfiles");

            migrationBuilder.DropIndex(
                name: "IX_AccountProfiles_ProfileName_Covering",
                table: "AccountProfiles");

            migrationBuilder.CreateIndex(
                name: "IX_AccountProfiles_AccountId",
                table: "AccountProfiles",
                column: "AccountId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AccountProfiles_ProfileName_Unique",
                table: "AccountProfiles",
                column: "ProfileName",
                unique: true,
                filter: "[IsDeleted] = 0");
        }
    }
}
