using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    public partial class AddCredentialsVersioning : Migration
    {
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
