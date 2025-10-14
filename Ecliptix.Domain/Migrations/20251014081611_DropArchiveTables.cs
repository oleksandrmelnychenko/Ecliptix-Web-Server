using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class DropArchiveTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Drop archive tables that were created during OptimizeSchemaWorldClass migration
            // These tables served their purpose during schema transition and are no longer needed
            migrationBuilder.Sql(@"
                IF EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[LoginAttempts_Archive_20251013]') AND type in (N'U'))
                BEGIN
                    DROP TABLE [dbo].[LoginAttempts_Archive_20251013];
                END
            ");

            migrationBuilder.Sql(@"
                IF EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[LogoutAudits_Archive_20251013]') AND type in (N'U'))
                BEGIN
                    DROP TABLE [dbo].[LogoutAudits_Archive_20251013];
                END
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Note: Down migration cannot recreate the archive tables with their original data
            // This is intentional as the archived data is no longer available
            // If rollback is needed, restore from database backup instead
        }
    }
}
