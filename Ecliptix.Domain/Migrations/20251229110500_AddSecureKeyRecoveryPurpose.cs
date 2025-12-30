using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    public partial class AddSecureKeyRecoveryPurpose : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CHK_VerificationFlows_Purpose",
                table: "VerificationFlows");

            migrationBuilder.AddCheckConstraint(
                name: "CHK_VerificationFlows_Purpose",
                table: "VerificationFlows",
                sql: "purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'secure_key_recovery', 'update_phone')");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CHK_VerificationFlows_Purpose",
                table: "VerificationFlows");

            migrationBuilder.AddCheckConstraint(
                name: "CHK_VerificationFlows_Purpose",
                table: "VerificationFlows",
                sql: "purpose IN ('unspecified', 'registration', 'login', 'password_recovery', 'update_phone')");
        }
    }
}
