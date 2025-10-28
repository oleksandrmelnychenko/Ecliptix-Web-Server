using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class FixInconsistentMembershipCreationStatus : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Fix existing memberships where CreationStatus is 'OtpVerified' but OPAQUE credentials exist
            // This is a data integrity issue where credentials were saved but status wasn't updated
            migrationBuilder.Sql(@"
                UPDATE m
                SET
                    m.CreationStatus = 'SecureKeySet',
                    m.UpdatedAt = SYSUTCDATETIME()
                FROM Memberships m
                INNER JOIN Accounts a ON a.MembershipId = m.UniqueId AND a.IsDeleted = 0
                INNER JOIN AccountSecureKeyAuth auth ON auth.AccountId = a.UniqueId
                    AND auth.IsPrimary = 1
                    AND auth.IsEnabled = 1
                    AND auth.IsDeleted = 0
                WHERE m.CreationStatus = 'OtpVerified'
                  AND m.IsDeleted = 0;
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Intentionally no rollback - this is a data fix for an inconsistent state
            // Reverting would reintroduce the data corruption
        }
    }
}
