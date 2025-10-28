using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class ExpandSecureKeyColumnFor208ByteRecords : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<byte[]>(
                name: "SecureKey",
                table: "AccountSecureKeyAuth",
                type: "VARBINARY(208)",
                nullable: false,
                oldClrType: typeof(byte[]),
                oldType: "VARBINARY(176)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<byte[]>(
                name: "SecureKey",
                table: "AccountSecureKeyAuth",
                type: "VARBINARY(176)",
                nullable: false,
                oldClrType: typeof(byte[]),
                oldType: "VARBINARY(208)");
        }
    }
}
