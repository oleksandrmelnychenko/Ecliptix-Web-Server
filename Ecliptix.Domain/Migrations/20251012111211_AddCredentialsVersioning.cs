using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class AddCredentialsVersioning : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "CredentialsVersion",
                table: "Memberships",
                type: "int",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<int>(
                name: "CredentialsVersion",
                table: "MasterKeyShares",
                type: "int",
                nullable: false,
                defaultValue: 1);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CredentialsVersion",
                table: "Memberships");

            migrationBuilder.DropColumn(
                name: "CredentialsVersion",
                table: "MasterKeyShares");
        }
    }
}
