using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class UpdateFailureSystemAndActorEvents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "VerificationFlows",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "pending",
                oldClrType: typeof(string),
                oldType: "nvarchar(20)",
                oldMaxLength: 20,
                oldDefaultValue: "Pending");

            migrationBuilder.AlterColumn<string>(
                name: "Purpose",
                table: "VerificationFlows",
                type: "nvarchar(30)",
                maxLength: 30,
                nullable: false,
                defaultValue: "unspecified",
                oldClrType: typeof(string),
                oldType: "nvarchar(30)",
                oldMaxLength: 30,
                oldDefaultValue: "Unspecified");

            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "OtpCodes",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "active",
                oldClrType: typeof(string),
                oldType: "nvarchar(20)",
                oldMaxLength: 20,
                oldDefaultValue: "Active");

            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "Memberships",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "inactive",
                oldClrType: typeof(string),
                oldType: "nvarchar(20)",
                oldMaxLength: 20,
                oldDefaultValue: "Inactive");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "VerificationFlows",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "Pending",
                oldClrType: typeof(string),
                oldType: "nvarchar(20)",
                oldMaxLength: 20,
                oldDefaultValue: "pending");

            migrationBuilder.AlterColumn<string>(
                name: "Purpose",
                table: "VerificationFlows",
                type: "nvarchar(30)",
                maxLength: 30,
                nullable: false,
                defaultValue: "Unspecified",
                oldClrType: typeof(string),
                oldType: "nvarchar(30)",
                oldMaxLength: 30,
                oldDefaultValue: "unspecified");

            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "OtpCodes",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "Active",
                oldClrType: typeof(string),
                oldType: "nvarchar(20)",
                oldMaxLength: 20,
                oldDefaultValue: "active");

            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "Memberships",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: false,
                defaultValue: "Inactive",
                oldClrType: typeof(string),
                oldType: "nvarchar(20)",
                oldMaxLength: 20,
                oldDefaultValue: "inactive");
        }
    }
}
