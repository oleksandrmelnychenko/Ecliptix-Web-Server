using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class RemoveAccountName : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Accounts_Membership_Active_Covering",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "AccountName",
                table: "Accounts");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Membership_Active_Covering",
                table: "Accounts",
                column: "MembershipId",
                filter: "IsDeleted = 0 AND Status = 1")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "AccountType", "IsDefaultAccount" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Accounts_Membership_Active_Covering",
                table: "Accounts");

            migrationBuilder.AddColumn<string>(
                name: "AccountName",
                table: "Accounts",
                type: "nvarchar(200)",
                maxLength: 200,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Membership_Active_Covering",
                table: "Accounts",
                column: "MembershipId",
                filter: "IsDeleted = 0 AND Status = 1")
                .Annotation("SqlServer:Include", new[] { "UniqueId", "AccountType", "AccountName", "IsDefaultAccount" });
        }
    }
}
