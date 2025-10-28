using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class Add_ResendAvailableAt_To_VerificationFlow : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ResendAvailableAt",
                table: "VerificationFlows",
                type: "datetimeoffset",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ResendAvailableAt",
                table: "VerificationFlows");
        }
    }
}
