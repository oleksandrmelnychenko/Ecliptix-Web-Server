using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.IdentityAccess.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class FixDefaultAccountActiveConstraint : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CHK_Accounts_Default_Active",
                table: "accounts");

            migrationBuilder.AddCheckConstraint(
                name: "CHK_Accounts_Default_Active",
                table: "accounts",
                sql: "(is_default_account = false) OR (status = 2)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CHK_Accounts_Default_Active",
                table: "accounts");

            migrationBuilder.AddCheckConstraint(
                name: "CHK_Accounts_Default_Active",
                table: "accounts",
                sql: "(is_default_account = false) OR (status != 2)");
        }
    }
}
