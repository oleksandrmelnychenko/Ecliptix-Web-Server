using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class RenameFriendEntityToMembershipRelation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Drop old indexes
            migrationBuilder.DropIndex(
                name: "IX_FriendEntity_CreatedAt",
                table: "FriendRelations");

            migrationBuilder.DropIndex(
                name: "IX_FriendEntity_UpdatedAt",
                table: "FriendRelations");

            migrationBuilder.DropIndex(
                name: "UQ_FriendEntity_UniqueId",
                table: "FriendRelations");

            migrationBuilder.DropIndex(
                name: "IX_Accounts_UserAId",
                table: "FriendRelations");

            migrationBuilder.DropIndex(
                name: "IX_Accounts_UserBId",
                table: "FriendRelations");

            migrationBuilder.DropIndex(
                name: "IX_Accounts_Status",
                table: "FriendRelations");

            // Rename columns
            migrationBuilder.RenameColumn(
                name: "UserAId",
                table: "FriendRelations",
                newName: "InitiatorId");

            migrationBuilder.RenameColumn(
                name: "UserBId",
                table: "FriendRelations",
                newName: "RecipientId");

            migrationBuilder.RenameColumn(
                name: "RequestedById",
                table: "FriendRelations",
                newName: "InitiatorAccountId");

            // Add new column
            migrationBuilder.AddColumn<int>(
                name: "RecipientAccountId",
                table: "FriendRelations",
                type: "int",
                nullable: false,
                defaultValue: 0);

            // Update Rejected status to Removed
            migrationBuilder.Sql("UPDATE FriendRelations SET Status = 'Removed' WHERE Status = 'Rejected'");

            // Rename table
            migrationBuilder.RenameTable(
                name: "FriendRelations",
                newName: "MembershipRelations");

            // Create new indexes
            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_CreatedAt",
                table: "MembershipRelations",
                column: "CreatedAt")
                .Annotation("SqlServer:Include", new[] { "UniqueId" });

            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_UpdatedAt",
                table: "MembershipRelations",
                column: "UpdatedAt")
                .Annotation("SqlServer:Include", new[] { "UniqueId" });

            migrationBuilder.CreateIndex(
                name: "UQ_MembershipRelations_UniqueId",
                table: "MembershipRelations",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_InitiatorId",
                table: "MembershipRelations",
                column: "InitiatorId")
                .Annotation("SqlServer:Where", "[IsDeleted] = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_RecipientId",
                table: "MembershipRelations",
                column: "RecipientId")
                .Annotation("SqlServer:Where", "[IsDeleted] = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_Status",
                table: "MembershipRelations",
                column: "Status")
                .Annotation("SqlServer:Where", "[IsDeleted] = 0");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Drop new indexes
            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_CreatedAt",
                table: "MembershipRelations");

            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_UpdatedAt",
                table: "MembershipRelations");

            migrationBuilder.DropIndex(
                name: "UQ_MembershipRelations_UniqueId",
                table: "MembershipRelations");

            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_InitiatorId",
                table: "MembershipRelations");

            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_RecipientId",
                table: "MembershipRelations");

            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_Status",
                table: "MembershipRelations");

            // Rename table back
            migrationBuilder.RenameTable(
                name: "MembershipRelations",
                newName: "FriendRelations");

            // Update Removed status back to Rejected
            migrationBuilder.Sql("UPDATE FriendRelations SET Status = 'Rejected' WHERE Status = 'Removed'");

            // Remove new column
            migrationBuilder.DropColumn(
                name: "RecipientAccountId",
                table: "FriendRelations");

            // Rename columns back
            migrationBuilder.RenameColumn(
                name: "InitiatorId",
                table: "FriendRelations",
                newName: "UserAId");

            migrationBuilder.RenameColumn(
                name: "RecipientId",
                table: "FriendRelations",
                newName: "UserBId");

            migrationBuilder.RenameColumn(
                name: "InitiatorAccountId",
                table: "FriendRelations",
                newName: "RequestedById");

            // Recreate old indexes
            migrationBuilder.CreateIndex(
                name: "IX_FriendEntity_CreatedAt",
                table: "FriendRelations",
                column: "CreatedAt")
                .Annotation("SqlServer:Include", new[] { "UniqueId" });

            migrationBuilder.CreateIndex(
                name: "IX_FriendEntity_UpdatedAt",
                table: "FriendRelations",
                column: "UpdatedAt")
                .Annotation("SqlServer:Include", new[] { "UniqueId" });

            migrationBuilder.CreateIndex(
                name: "UQ_FriendEntity_UniqueId",
                table: "FriendRelations",
                column: "UniqueId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_UserAId",
                table: "FriendRelations",
                column: "UserAId")
                .Annotation("SqlServer:Where", "[IsDeleted] = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_UserBId",
                table: "FriendRelations",
                column: "UserBId")
                .Annotation("SqlServer:Where", "[IsDeleted] = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Status",
                table: "FriendRelations",
                column: "Status")
                .Annotation("SqlServer:Where", "[IsDeleted] = 0");
        }
    }
}

