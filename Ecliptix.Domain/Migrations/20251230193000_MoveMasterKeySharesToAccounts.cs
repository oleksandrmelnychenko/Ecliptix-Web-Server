using System;
using Ecliptix.Domain.Schema;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations;

[DbContext(typeof(EcliptixSchemaContext))]
[Migration("20251230193000_MoveMasterKeySharesToAccounts")]
public partial class MoveMasterKeySharesToAccounts : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey(
            name: "FK_MasterKeyShares_Memberships",
            table: "MasterKeyShares");

        migrationBuilder.DropIndex(
            name: "UQ_MasterKeyShares_MembershipShare",
            table: "MasterKeyShares");

        migrationBuilder.RenameColumn(
            name: "membership_unique_id",
            table: "MasterKeyShares",
            newName: "account_unique_id");

        if (ActiveProvider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            migrationBuilder.Sql(
                """
                UPDATE m
                SET account_unique_id = a.unique_id
                FROM MasterKeyShares m
                INNER JOIN Accounts a
                    ON a.membership_id = m.account_unique_id
                   AND a.is_default_account = 1
                   AND a.is_deleted = 0;

                DELETE FROM MasterKeyShares
                WHERE NOT EXISTS (
                    SELECT 1 FROM Accounts a
                    WHERE a.unique_id = MasterKeyShares.account_unique_id
                      AND a.is_deleted = 0
                );
                """);
        }
        else
        {
            migrationBuilder.Sql(
                """
                UPDATE "MasterKeyShares" m
                SET "account_unique_id" = a."unique_id"
                FROM "Accounts" a
                WHERE a."membership_id" = m."account_unique_id"
                  AND a."is_default_account" = TRUE
                  AND a."is_deleted" = FALSE;

                DELETE FROM "MasterKeyShares" m
                WHERE NOT EXISTS (
                    SELECT 1 FROM "Accounts" a
                    WHERE a."unique_id" = m."account_unique_id"
                      AND a."is_deleted" = FALSE
                );
                """);
        }

        migrationBuilder.CreateIndex(
            name: "UQ_MasterKeyShares_AccountShare",
            table: "MasterKeyShares",
            columns: new[] { "account_unique_id", "share_index" },
            unique: true);

        migrationBuilder.AddForeignKey(
            name: "FK_MasterKeyShares_Accounts",
            table: "MasterKeyShares",
            column: "account_unique_id",
            principalTable: "Accounts",
            principalColumn: "unique_id",
            onDelete: ReferentialAction.NoAction);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropForeignKey(
            name: "FK_MasterKeyShares_Accounts",
            table: "MasterKeyShares");

        migrationBuilder.DropIndex(
            name: "UQ_MasterKeyShares_AccountShare",
            table: "MasterKeyShares");

        migrationBuilder.RenameColumn(
            name: "account_unique_id",
            table: "MasterKeyShares",
            newName: "membership_unique_id");

        if (ActiveProvider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            migrationBuilder.Sql(
                """
                UPDATE m
                SET membership_unique_id = a.membership_id
                FROM MasterKeyShares m
                INNER JOIN Accounts a
                    ON a.unique_id = m.membership_unique_id
                   AND a.is_deleted = 0;
                """);
        }
        else
        {
            migrationBuilder.Sql(
                """
                UPDATE "MasterKeyShares" m
                SET "membership_unique_id" = a."membership_id"
                FROM "Accounts" a
                WHERE a."unique_id" = m."membership_unique_id"
                  AND a."is_deleted" = FALSE;
                """);
        }

        migrationBuilder.CreateIndex(
            name: "UQ_MasterKeyShares_MembershipShare",
            table: "MasterKeyShares",
            columns: new[] { "membership_unique_id", "share_index" },
            unique: true);

        migrationBuilder.AddForeignKey(
            name: "FK_MasterKeyShares_Memberships",
            table: "MasterKeyShares",
            column: "membership_unique_id",
            principalTable: "Memberships",
            principalColumn: "unique_id",
            onDelete: ReferentialAction.NoAction);
    }
}
