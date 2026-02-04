using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.IdentityAccess.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddProfileSetStatus : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CHK_Memberships_CreationStatus",
                table: "memberships");

            migrationBuilder.AddCheckConstraint(
                name: "CHK_Memberships_CreationStatus",
                table: "memberships",
                sql: "creation_status IN ('otp_verified', 'secure_key_set', 'profile_set', 'passphrase_set')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CHK_Memberships_CreationStatus",
                table: "memberships");

            migrationBuilder.AddCheckConstraint(
                name: "CHK_Memberships_CreationStatus",
                table: "memberships",
                sql: "creation_status IN ('otp_verified', 'secure_key_set', 'passphrase_set')");
        }
    }
}
