using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class Add_LastOtpSentAt_And_CooldownCheck : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastOtpSentAt",
                table: "VerificationFlows",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_VerificationFlows_CooldownCheck",
                table: "VerificationFlows",
                columns: new[] { "UniqueId", "LastOtpSentAt", "OtpCount", "ExpiresAt" },
                filter: "IsDeleted = 0 AND Status = 'pending'");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_VerificationFlows_CooldownCheck",
                table: "VerificationFlows");

            migrationBuilder.DropColumn(
                name: "LastOtpSentAt",
                table: "VerificationFlows");
        }
    }
}
