using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    public partial class DropArchiveTables : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
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

        protected override void Down(MigrationBuilder migrationBuilder)
        {
        }
    }
}
