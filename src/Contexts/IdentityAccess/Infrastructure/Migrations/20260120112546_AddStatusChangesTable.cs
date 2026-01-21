using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Ecliptix.IdentityAccess.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddStatusChangesTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "status_changes",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    entity_type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    entity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    property_name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    from_value = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    to_value = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    changed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    membership_id = table.Column<Guid>(type: "uuid", nullable: true),
                    account_id = table.Column<Guid>(type: "uuid", nullable: true),
                    device_id = table.Column<Guid>(type: "uuid", nullable: true),
                    source = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    reason = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    correlation_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    metadata = table.Column<string>(type: "jsonb", nullable: true),
                    unique_id = table.Column<Guid>(type: "uuid", nullable: false, defaultValueSql: "gen_random_uuid()"),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "CURRENT_TIMESTAMP"),
                    is_deleted = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    row_version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false, defaultValue: new byte[] { 0 })
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_status_changes", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_StatusChanges_ChangedAt",
                table: "status_changes",
                column: "changed_at",
                descending: new bool[0]);

            migrationBuilder.CreateIndex(
                name: "IX_StatusChanges_Entity_ChangedAt",
                table: "status_changes",
                columns: new[] { "entity_type", "entity_id", "changed_at" },
                descending: new[] { false, false, true });

            migrationBuilder.CreateIndex(
                name: "IX_StatusChanges_ToValue",
                table: "status_changes",
                columns: new[] { "entity_type", "property_name", "to_value", "changed_at" },
                descending: new[] { false, false, false, true });

            migrationBuilder.CreateIndex(
                name: "UQ_StatusChangeEntity_UniqueId",
                table: "status_changes",
                column: "unique_id",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "status_changes");
        }
    }
}
