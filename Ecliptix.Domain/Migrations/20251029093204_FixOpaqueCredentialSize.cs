using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class FixOpaqueCredentialSize : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                "DELETE FROM [AccountSecureKeyAuth] WHERE 1=1;",
                suppressTransaction: false);

            migrationBuilder.AlterColumn<byte[]>(
                name: "SecureKey",
                table: "AccountSecureKeyAuth",
                type: "VARBINARY(240)",
                nullable: false,
                oldClrType: typeof(byte[]),
                oldType: "VARBINARY(208)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<byte[]>(
                name: "SecureKey",
                table: "AccountSecureKeyAuth",
                type: "VARBINARY(208)",
                nullable: false,
                oldClrType: typeof(byte[]),
                oldType: "VARBINARY(240)");
        }
    }
}
