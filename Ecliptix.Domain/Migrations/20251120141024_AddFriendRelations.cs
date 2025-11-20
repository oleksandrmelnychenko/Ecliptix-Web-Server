using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Ecliptix.Domain.Migrations
{
    /// <inheritdoc />
    public partial class AddFriendRelations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "FriendRelations",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserAId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserBId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RequestedById = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    AcceptedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    Message = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: true),
                    MetaJson = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    UniqueId = table.Column<Guid>(type: "uniqueidentifier", nullable: false, defaultValueSql: "NEWID()"),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSDATETIMEOFFSET()"),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false, defaultValueSql: "SYSDATETIMEOFFSET()"),
                    IsDeleted = table.Column<bool>(type: "bit", nullable: false, defaultValue: false),
                    RowVersion = table.Column<byte[]>(type: "rowversion", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FriendRelations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_Status",
                table: "FriendRelations",
                column: "Status",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_UserAId",
                table: "FriendRelations",
                column: "UserAId",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_UserBId",
                table: "FriendRelations",
                column: "UserBId",
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_FriendEntity_CreatedAt",
                table: "FriendRelations",
                column: "CreatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "IX_FriendEntity_UpdatedAt",
                table: "FriendRelations",
                column: "UpdatedAt",
                descending: new bool[0],
                filter: "IsDeleted = 0");

            migrationBuilder.CreateIndex(
                name: "UQ_FriendEntity_UniqueId",
                table: "FriendRelations",
                column: "UniqueId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FriendRelations");
        }
    }
}
