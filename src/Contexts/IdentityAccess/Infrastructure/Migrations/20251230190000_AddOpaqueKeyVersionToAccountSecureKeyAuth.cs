using System;
using Ecliptix.IdentityAccess.Domain.Schema;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.IdentityAccess.Infrastructure.Migrations;

[DbContext(typeof(EcliptixSchemaContext))]
[Migration("20251230190000_AddOpaqueKeyVersionToAccountSecureKeyAuth")]
public partial class AddOpaqueKeyVersionToAccountSecureKeyAuth : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<int>(
            name: "opaque_key_version",
            table: "AccountSecureKeyAuth",
            type: "integer",
            nullable: false,
            defaultValue: 1);

        if (ActiveProvider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            migrationBuilder.Sql(
                "UPDATE [AccountSecureKeyAuth] SET [opaque_key_version] = 1 WHERE [opaque_key_version] IS NULL;");
        }
        else
        {
            migrationBuilder.Sql(
                "UPDATE \"AccountSecureKeyAuth\" SET \"opaque_key_version\" = 1 WHERE \"opaque_key_version\" IS NULL;");
        }
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "opaque_key_version",
            table: "AccountSecureKeyAuth");
    }
}
