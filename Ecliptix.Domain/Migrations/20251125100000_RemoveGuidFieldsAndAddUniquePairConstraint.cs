using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class RemoveGuidFieldsAndAddUniquePairConstraint : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Drop old indexes on GUID fields
            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_InitiatorId",
                table: "MembershipRelations");

            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_RecipientId",
                table: "MembershipRelations");

            // Remove GUID columns (InitiatorId, RecipientId) - not needed for FK relationships
            migrationBuilder.DropColumn(
                name: "InitiatorId",
                table: "MembershipRelations");

            migrationBuilder.DropColumn(
                name: "RecipientId",
                table: "MembershipRelations");

            // Create indexes on int AccountId fields for efficient JOINs
            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_InitiatorAccountId",
                table: "MembershipRelations",
                column: "InitiatorAccountId",
                filter: "[IsDeleted] = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_RecipientAccountId",
                table: "MembershipRelations",
                column: "RecipientAccountId",
                filter: "[IsDeleted] = 0");

            // Composite index for lookups
            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_InitiatorRecipient",
                table: "MembershipRelations",
                columns: new[] { "InitiatorAccountId", "RecipientAccountId" },
                filter: "[IsDeleted] = 0");

            // Add computed columns for normalized pair (AccountA = MIN, AccountB = MAX)
            migrationBuilder.Sql(@"
                ALTER TABLE [dbo].[MembershipRelations]
                ADD [AccountA] AS (CASE WHEN [InitiatorAccountId] < [RecipientAccountId] 
                                        THEN [InitiatorAccountId] 
                                        ELSE [RecipientAccountId] END) PERSISTED;
            ");

            migrationBuilder.Sql(@"
                ALTER TABLE [dbo].[MembershipRelations]
                ADD [AccountB] AS (CASE WHEN [InitiatorAccountId] < [RecipientAccountId] 
                                        THEN [RecipientAccountId] 
                                        ELSE [InitiatorAccountId] END) PERSISTED;
            ");

            // Create unique index on normalized pair to prevent duplicates (A->B and B->A)
            migrationBuilder.Sql(@"
                CREATE UNIQUE INDEX [UQ_MembershipRelations_AccountPair]
                ON [dbo].[MembershipRelations] ([AccountA], [AccountB])
                WHERE [IsDeleted] = 0;
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Drop unique constraint
            migrationBuilder.Sql(@"
                DROP INDEX [UQ_MembershipRelations_AccountPair] ON [dbo].[MembershipRelations];
            ");

            // Drop computed columns
            migrationBuilder.DropColumn(
                name: "AccountA",
                table: "MembershipRelations");

            migrationBuilder.DropColumn(
                name: "AccountB",
                table: "MembershipRelations");

            // Drop new indexes
            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_InitiatorAccountId",
                table: "MembershipRelations");

            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_RecipientAccountId",
                table: "MembershipRelations");

            migrationBuilder.DropIndex(
                name: "IX_MembershipRelations_InitiatorRecipient",
                table: "MembershipRelations");

            // Re-add GUID columns
            migrationBuilder.AddColumn<Guid>(
                name: "InitiatorId",
                table: "MembershipRelations",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: Guid.Empty);

            migrationBuilder.AddColumn<Guid>(
                name: "RecipientId",
                table: "MembershipRelations",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: Guid.Empty);

            // Recreate old indexes on GUIDs
            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_InitiatorId",
                table: "MembershipRelations",
                column: "InitiatorId",
                filter: "[IsDeleted] = 0");

            migrationBuilder.CreateIndex(
                name: "IX_MembershipRelations_RecipientId",
                table: "MembershipRelations",
                column: "RecipientId",
                filter: "[IsDeleted] = 0");
        }
    }
}

