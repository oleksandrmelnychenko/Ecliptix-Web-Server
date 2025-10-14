using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class RenameUserAgentToPlatformAndAddToLogoutAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "UserAgent",
                table: "LoginAttempts");

            migrationBuilder.AddColumn<string>(
                name: "Platform",
                table: "LogoutAudits",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Platform",
                table: "LoginAttempts",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Platform",
                table: "LogoutAudits");

            migrationBuilder.DropColumn(
                name: "Platform",
                table: "LoginAttempts");

            migrationBuilder.AddColumn<string>(
                name: "UserAgent",
                table: "LoginAttempts",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: true);
        }
    }
}
