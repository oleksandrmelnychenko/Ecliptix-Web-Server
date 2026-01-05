# 🐘 Complete PostgreSQL Setup Guide for Ecliptix

**Date:** December 2, 2025
**Project:** Ecliptix
**.NET Version:** 10.0
**EF Core Version:** 9.x
**DbContext:** `EcliptixSchemaContext`

---

## 📋 Table of Contents

1. [Docker PostgreSQL Setup](#task-1-docker-postgresql-setup)
2. [Environment Variables](#task-2-environment-variables)
3. [Connection String Configuration](#task-3-connection-string-configuration)
4. [Install Npgsql & Configure EF Core](#task-4-install-npgsql--configure-ef-core)
5. [Create & Apply Migrations](#task-5-create--apply-migrations)
6. [Helper Scripts](#task-6-helper-scripts)
7. [Verification](#task-7-verification)
8. [Troubleshooting](#troubleshooting)

---

## ✅ Task 1: Docker PostgreSQL Setup

### Files Created:
1. ✅ `docker-compose.yml` - DONE (updated with PostgreSQL + pgAdmin)
2. ✅ `.env.example` - DONE
3. ✅ `.env` - DONE (copied from example)

### Start PostgreSQL Container

```bash
# Start all services (PostgreSQL, pgAdmin, Redis)
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs postgres
docker-compose logs pgadmin

# Expected output:
# ✅ ecliptix_postgres   running   0.0.0.0:5432->5432/tcp
# ✅ ecliptix_pgadmin    running   0.0.0.0:5050->80/tcp
# ✅ ecliptix_redis      running   0.0.0.0:6379->6379/tcp
```

### Access pgAdmin

1. Open browser: http://localhost:5050
2. Login:
   - Email: `admin@ecliptix.local`
   - Password: `Admin_2024`
3. Add Server:
   - Name: `Ecliptix Local`
   - Host: `postgres` (container name)
   - Port: `5432`
   - Username: `ecliptix_admin`
   - Password: `Dev_Password_2024`
   - Database: `ecliptix_memberships`

---

## ✅ Task 2: Environment Variables

### .env File (Already Created)

Located at: `/Users/oleksandrmelnychenko/RiderProjects/Ecliptix/.env`

```.env
# PostgreSQL Configuration
POSTGRES_USER=ecliptix_admin
POSTGRES_PASSWORD=Dev_Password_2024
POSTGRES_DB=ecliptix_memberships

# pgAdmin Configuration
PGADMIN_EMAIL=admin@ecliptix.local
PGADMIN_PASSWORD=Admin_2024
```

**IMPORTANT:** `.env` is git-ignored for security!

---

## ✅ Task 3: Connection String Configuration

### Step 1: Create appsettings.Development.Local.json

This file will override connection strings for local PostgreSQL development.

**File:** `Ecliptix.Core/appsettings.Development.Local.json`

```json
{
  "ConnectionStrings": {
    "EcliptixMemberships": "Host=localhost;Port=5432;Database=ecliptix_memberships;Username=ecliptix_admin;Password=Dev_Password_2024;Pooling=True;Minimum Pool Size=20;Maximum Pool Size=200;Connection Idle Lifetime=300;Connection Pruning Interval=10;Include Error Detail=true;Log Parameters=true;Application Name=Ecliptix.Core"
  },
  "Serilog": {
    "MinimumLevel": {
      "Default": "Debug",
      "Override": {
        "Microsoft.EntityFrameworkCore.Database.Command": "Information",
        "Microsoft.EntityFrameworkCore.Infrastructure": "Warning"
      }
    }
  }
}
```

**Connection String Parameters Explained:**
- `Host=localhost` - Docker container mapped to localhost
- `Port=5432` - PostgreSQL default port
- `Database=ecliptix_memberships` - Database name from .env
- `Username=ecliptix_admin` - User from .env
- `Password=Dev_Password_2024` - Password from .env
- `Pooling=True` - Enable connection pooling
- `Minimum Pool Size=20` - Keep 20 warm connections
- `Maximum Pool Size=200` - Max 200 concurrent connections
- `Connection Idle Lifetime=300` - Close idle connections after 5 minutes
- `Connection Pruning Interval=10` - Check for idle connections every 10 seconds
- `Include Error Detail=true` - Show detailed errors (DEV ONLY)
- `Log Parameters=true` - Log SQL parameters (DEV ONLY)
- `Application Name=Ecliptix.Core` - Identify app in PostgreSQL logs

### Step 2: Alternative - Use User Secrets (Recommended for Production-like)

```bash
cd Ecliptix.Core

# Initialize user secrets
dotnet user-secrets init

# Set connection string
dotnet user-secrets set "ConnectionStrings:EcliptixMemberships" "Host=localhost;Port=5432;Database=ecliptix_memberships;Username=ecliptix_admin;Password=Dev_Password_2024;Pooling=True;Minimum Pool Size=20;Maximum Pool Size=200"

# List secrets
dotnet user-secrets list

# Remove specific secret
dotnet user-secrets remove "ConnectionStrings:EcliptixMemberships"

# Clear all secrets
dotnet user-secrets clear
```

**User Secrets Location (macOS):**
```
~/.microsoft/usersecrets/<user_secrets_id>/secrets.json
```

---

## ✅ Task 4: Install Npgsql & Configure EF Core

### Step 1: Install Required NuGet Packages

```bash
cd /Users/oleksandrmelnychenko/RiderProjects/Ecliptix

# Install Npgsql Entity Framework Core Provider
dotnet add src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj package Npgsql.EntityFrameworkCore.PostgreSQL --version 9.0.0

# Install EF Core Design Tools (if not already installed)
dotnet add src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj package Microsoft.EntityFrameworkCore.Design --version 9.0.0

# Install Npgsql for snake_case naming convention
dotnet add src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj package EFCore.NamingConventions --version 9.0.0

# Verify installations
dotnet list src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj package | grep -E "Npgsql|EntityFrameworkCore"
```

### Step 2: Update Program.cs for PostgreSQL

**File:** `Ecliptix.Core/Program.cs`

Find the existing `ConfigureServices` method and update the DbContext registration:

```csharp
static void ConfigureServices(WebApplicationBuilder builder)
{
    // Determine which database provider to use
    bool usePostgreSQL = builder.Configuration.GetValue<bool>("UsePostgreSQL", defaultValue: false);

    if (usePostgreSQL)
    {
        // PostgreSQL Configuration
        builder.Services.AddPooledDbContextFactory<EcliptixSchemaContext>(options =>
        {
            string? connectionString = builder.Configuration.GetConnectionString("EcliptixMemberships");

            options.UseNpgsql(connectionString, npgsqlOptions =>
            {
                int commandTimeout = (int)TimeoutConfiguration.Database.CommandTimeout.TotalSeconds;
                npgsqlOptions.CommandTimeout(commandTimeout == int.MaxValue ? 0 : commandTimeout);

                // Automatic retry with exponential backoff (for transient failures)
                npgsqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 3,
                    maxRetryDelay: TimeSpan.FromSeconds(5),
                    errorCodesToAdd: null);

                // Split queries by default for better performance
                npgsqlOptions.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);

                // Use relational nulls for better SQL compatibility
                npgsqlOptions.UseRelationalNulls(false);

                // Map DateTime to timestamp without time zone (UTC)
                npgsqlOptions.MapRange<DateTimeOffset>();

                // Enable reverse-null check for better PostgreSQL compatibility
                npgsqlOptions.SetPostgresVersion(new Version(16, 0));
            })
            .UseSnakeCaseNamingConvention() // Convert C# PascalCase to PostgreSQL snake_case
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
            .EnableSensitiveDataLogging(builder.Environment.IsDevelopment())
            .EnableDetailedErrors(builder.Environment.IsDevelopment());
        }, poolSize: 128);
    }
    else
    {
        // SQL Server Configuration (existing code)
        builder.Services.AddPooledDbContextFactory<EcliptixSchemaContext>(options =>
        {
            string? connectionString = builder.Configuration.GetConnectionString("EcliptixMemberships");
            options.UseSqlServer(connectionString, sqlOptions =>
            {
                int commandTimeout = (int)TimeoutConfiguration.Database.CommandTimeout.TotalSeconds;
                sqlOptions.CommandTimeout(commandTimeout == int.MaxValue ? 0 : commandTimeout);

                sqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 3,
                    maxRetryDelay: TimeSpan.FromSeconds(5),
                    errorNumbersToAdd: null);

                sqlOptions.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);
                sqlOptions.UseRelationalNulls(false);
            })
            .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking)
            .EnableSensitiveDataLogging(false)
            .EnableDetailedErrors(false);
        }, poolSize: 128);
    }

    // ... rest of your existing configuration
}
```

### Step 3: Add Provider Configuration to appsettings

**File:** `Ecliptix.Core/appsettings.Development.Local.json`

Add this property:

```json
{
  "UsePostgreSQL": true,
  "ConnectionStrings": {
    "EcliptixMemberships": "Host=localhost;Port=5432;..."
  }
}
```

### Step 4: Update EntityBaseMap for PostgreSQL

**File:** `src/Contexts/IdentityAccess/Domain/Schema/EntityBaseMap.cs`

The current code uses SQL Server specific functions. Update it to be database-agnostic:

```csharp
public override void Map(EntityTypeBuilder<T> entity)
{
    entity.HasKey(e => e.Id);
    entity.Property(e => e.Id).UseIdentityColumn(); // Works for both SQL Server & PostgreSQL

    // Use default values that work across providers
    entity.Property(e => e.UniqueId).HasDefaultValueSql("gen_random_uuid()"); // PostgreSQL
    // For SQL Server, this will need to be: NEWID()

    entity.Property(e => e.CreatedAt).HasDefaultValueSql("CURRENT_TIMESTAMP");
    entity.Property(e => e.UpdatedAt).HasDefaultValueSql("CURRENT_TIMESTAMP");
    entity.Property(e => e.IsDeleted).HasDefaultValue(false);

    entity.Property(e => e.RowVersion)
        .IsRowVersion()
        .IsConcurrencyToken();

    entity.HasQueryFilter(e => !e.IsDeleted);
    ConfigureIndexes(entity);
}
```

**Better Approach:** Create provider-specific configurations using IDesignTimeDbContextFactory.

---

## ✅ Task 5: Create & Apply Migrations

### Step 1: Install EF Core Tools (if needed)

```bash
# Check if installed
dotnet ef --version

# If not installed:
dotnet tool install --global dotnet-ef --version 9.0.0

# Or update existing:
dotnet tool update --global dotnet-ef
```

### Step 2: Create Initial PostgreSQL Migration

```bash
cd /Users/oleksandrmelnychenko/RiderProjects/Ecliptix

# Remove existing SQL Server migrations (optional - if starting fresh with PostgreSQL)
# rm -rf src/Contexts/IdentityAccess/Infrastructure/Migrations/*

# Create new migration for PostgreSQL
dotnet ef migrations add InitialPostgreSQLMigration \
  --project src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj \
  --startup-project Ecliptix.Core/Ecliptix.Core.csproj \
  --context EcliptixSchemaContext \
  --output-dir Migrations/PostgreSQL

# Review the generated migration
cat src/Contexts/IdentityAccess/Infrastructure/Migrations/PostgreSQL/*_InitialPostgreSQLMigration.cs
```

### Step 3: Apply Migration to PostgreSQL

```bash
# Ensure PostgreSQL container is running
docker-compose ps | grep postgres

# Apply migration
dotnet ef database update \
  --project src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj \
  --startup-project Ecliptix.Core/Ecliptix.Core.csproj \
  --context EcliptixSchemaContext

# Expected output:
# Build started...
# Build succeeded.
# info: Microsoft.EntityFrameworkCore.Database.Command[20101]
#       Executed DbCommand (XXms) [Parameters=[], CommandType='Text', CommandTimeout='30']
#       CREATE TABLE ...
# Done.
```

### Step 4: Verify Migration Applied

```bash
# Connect to PostgreSQL container
docker exec -it ecliptix_postgres psql -U ecliptix_admin -d ecliptix_memberships

# List all tables
\dt

# Describe a specific table
\d "Accounts"

# Check migration history
SELECT * FROM "__EFMigrationsHistory";

# Exit psql
\q
```

### Step 5: Generate SQL Script (for review/documentation)

```bash
# Generate SQL script from migrations
dotnet ef migrations script \
  --project src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj \
  --startup-project Ecliptix.Core/Ecliptix.Core.csproj \
  --context EcliptixSchemaContext \
  --output Scripts/migrations-postgres.sql \
  --idempotent

# Review the generated SQL
cat Scripts/migrations-postgres.sql
```

---

## ✅ Task 6: Helper Scripts

### PowerShell Script: dev-db.ps1

**File:** `Scripts/dev-db.ps1`

```powershell
#!/usr/bin/env pwsh
# Ecliptix PostgreSQL Development Database Helper Script

param(
    [Parameter(Position=0)]
    [ValidateSet('up', 'down', 'restart', 'reset', 'migrate', 'new', 'status', 'logs', 'psql', 'backup', 'restore')]
    [string]$Command = 'status',

    [Parameter(Position=1)]
    [string]$Arg = ''
)

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DomainProject = Join-Path $ProjectRoot "src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj"
$StartupProject = Join-Path $ProjectRoot "Ecliptix.Core/Ecliptix.Core.csproj"
$BackupDir = Join-Path $ProjectRoot "Backups"

function Write-Success { Write-Host "✅ $args" -ForegroundColor Green }
function Write-Info { Write-Host "ℹ️  $args" -ForegroundColor Cyan }
function Write-Warning { Write-Host "⚠️  $args" -ForegroundColor Yellow }
function Write-Error { Write-Host "❌ $args" -ForegroundColor Red }

switch ($Command) {
    'up' {
        Write-Info "Starting PostgreSQL container..."
        docker-compose up -d postgres pgadmin
        Start-Sleep -Seconds 5
        docker-compose ps | Select-String "ecliptix_postgres"
        Write-Success "PostgreSQL is running on localhost:5432"
        Write-Info "pgAdmin is running on http://localhost:5050"
    }

    'down' {
        Write-Info "Stopping PostgreSQL container..."
        docker-compose down
        Write-Success "PostgreSQL stopped"
    }

    'restart' {
        Write-Info "Restarting PostgreSQL..."
        docker-compose restart postgres
        Start-Sleep -Seconds 3
        Write-Success "PostgreSQL restarted"
    }

    'reset' {
        Write-Warning "This will DELETE all data in the database!"
        $confirm = Read-Host "Are you sure? (yes/no)"
        if ($confirm -eq 'yes') {
            Write-Info "Stopping containers..."
            docker-compose down

            Write-Info "Removing PostgreSQL volume..."
            docker volume rm ecliptix_postgres_data -f

            Write-Info "Starting PostgreSQL..."
            docker-compose up -d postgres
            Start-Sleep -Seconds 5

            Write-Info "Applying migrations..."
            dotnet ef database update `
                --project $DomainProject `
                --startup-project $StartupProject `
                --context EcliptixSchemaContext

            Write-Success "Database reset complete!"
        } else {
            Write-Warning "Reset cancelled"
        }
    }

    'migrate' {
        Write-Info "Applying pending migrations..."
        dotnet ef database update `
            --project $DomainProject `
            --startup-project $StartupProject `
            --context EcliptixSchemaContext
        Write-Success "Migrations applied"
    }

    'new' {
        if ([string]::IsNullOrEmpty($Arg)) {
            Write-Error "Migration name required: ./dev-db.ps1 new MigrationName"
            exit 1
        }
        Write-Info "Creating new migration: $Arg"
        dotnet ef migrations add $Arg `
            --project $DomainProject `
            --startup-project $StartupProject `
            --context EcliptixSchemaContext `
            --output-dir Migrations/PostgreSQL
        Write-Success "Migration created: $Arg"
    }

    'status' {
        Write-Info "Migration Status:"
        dotnet ef migrations list `
            --project $DomainProject `
            --startup-project $StartupProject `
            --context EcliptixSchemaContext

        Write-Info ""
        Write-Info "Container Status:"
        docker-compose ps | Select-String "postgres"
    }

    'logs' {
        Write-Info "PostgreSQL Logs (last 50 lines):"
        docker-compose logs --tail=50 postgres
    }

    'psql' {
        Write-Info "Connecting to PostgreSQL..."
        docker exec -it ecliptix_postgres psql -U ecliptix_admin -d ecliptix_memberships
    }

    'backup' {
        if (-not (Test-Path $BackupDir)) {
            New-Item -ItemType Directory -Path $BackupDir | Out-Null
        }
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = Join-Path $BackupDir "ecliptix_$timestamp.sql"

        Write-Info "Creating backup: $backupFile"
        docker exec ecliptix_postgres pg_dump -U ecliptix_admin -d ecliptix_memberships > $backupFile
        Write-Success "Backup created: $backupFile"
    }

    'restore' {
        if ([string]::IsNullOrEmpty($Arg)) {
            Write-Error "Backup file required: ./dev-db.ps1 restore path/to/backup.sql"
            exit 1
        }
        if (-not (Test-Path $Arg)) {
            Write-Error "Backup file not found: $Arg"
            exit 1
        }
        Write-Warning "This will OVERWRITE the current database!"
        $confirm = Read-Host "Are you sure? (yes/no)"
        if ($confirm -eq 'yes') {
            Write-Info "Restoring from: $Arg"
            Get-Content $Arg | docker exec -i ecliptix_postgres psql -U ecliptix_admin -d ecliptix_memberships
            Write-Success "Database restored"
        } else {
            Write-Warning "Restore cancelled"
        }
    }

    default {
        Write-Info "Ecliptix PostgreSQL Helper Script"
        Write-Info "Usage: ./dev-db.ps1 <command> [args]"
        Write-Info ""
        Write-Info "Commands:"
        Write-Info "  up         - Start PostgreSQL container"
        Write-Info "  down       - Stop PostgreSQL container"
        Write-Info "  restart    - Restart PostgreSQL"
        Write-Info "  reset      - Drop & recreate database (DESTRUCTIVE)"
        Write-Info "  migrate    - Apply pending migrations"
        Write-Info "  new <name> - Create new migration"
        Write-Info "  status     - Show migration & container status"
        Write-Info "  logs       - Show PostgreSQL logs"
        Write-Info "  psql       - Connect to PostgreSQL CLI"
        Write-Info "  backup     - Create database backup"
        Write-Info "  restore <file> - Restore from backup"
    }
}
```

### Bash Script: dev-db.sh (for macOS/Linux)

**File:** `Scripts/dev-db.sh`

```bash
#!/bin/bash

# Ecliptix PostgreSQL Development Database Helper Script

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOMAIN_PROJECT="$PROJECT_ROOT/src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj"
STARTUP_PROJECT="$PROJECT_ROOT/Ecliptix.Core/Ecliptix.Core.csproj"
BACKUP_DIR="$PROJECT_ROOT/Backups"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}✅ $1${NC}"; }
info() { echo -e "${CYAN}ℹ️  $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

CMD="${1:-status}"
ARG="${2}"

case "$CMD" in
    up)
        info "Starting PostgreSQL container..."
        docker-compose up -d postgres pgadmin
        sleep 5
        docker-compose ps | grep ecliptix_postgres
        success "PostgreSQL is running on localhost:5432"
        info "pgAdmin is running on http://localhost:5050"
        ;;

    down)
        info "Stopping PostgreSQL container..."
        docker-compose down
        success "PostgreSQL stopped"
        ;;

    restart)
        info "Restarting PostgreSQL..."
        docker-compose restart postgres
        sleep 3
        success "PostgreSQL restarted"
        ;;

    reset)
        warning "This will DELETE all data in the database!"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            info "Stopping containers..."
            docker-compose down

            info "Removing PostgreSQL volume..."
            docker volume rm ecliptix_postgres_data -f

            info "Starting PostgreSQL..."
            docker-compose up -d postgres
            sleep 5

            info "Applying migrations..."
            dotnet ef database update \
                --project "$DOMAIN_PROJECT" \
                --startup-project "$STARTUP_PROJECT" \
                --context EcliptixSchemaContext

            success "Database reset complete!"
        else
            warning "Reset cancelled"
        fi
        ;;

    migrate)
        info "Applying pending migrations..."
        dotnet ef database update \
            --project "$DOMAIN_PROJECT" \
            --startup-project "$STARTUP_PROJECT" \
            --context EcliptixSchemaContext
        success "Migrations applied"
        ;;

    new)
        if [ -z "$ARG" ]; then
            error "Migration name required: ./dev-db.sh new MigrationName"
            exit 1
        fi
        info "Creating new migration: $ARG"
        dotnet ef migrations add "$ARG" \
            --project "$DOMAIN_PROJECT" \
            --startup-project "$STARTUP_PROJECT" \
            --context EcliptixSchemaContext \
            --output-dir Migrations/PostgreSQL
        success "Migration created: $ARG"
        ;;

    status)
        info "Migration Status:"
        dotnet ef migrations list \
            --project "$DOMAIN_PROJECT" \
            --startup-project "$STARTUP_PROJECT" \
            --context EcliptixSchemaContext

        echo ""
        info "Container Status:"
        docker-compose ps | grep postgres
        ;;

    logs)
        info "PostgreSQL Logs (last 50 lines):"
        docker-compose logs --tail=50 postgres
        ;;

    psql)
        info "Connecting to PostgreSQL..."
        docker exec -it ecliptix_postgres psql -U ecliptix_admin -d ecliptix_memberships
        ;;

    backup)
        mkdir -p "$BACKUP_DIR"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BACKUP_FILE="$BACKUP_DIR/ecliptix_$TIMESTAMP.sql"

        info "Creating backup: $BACKUP_FILE"
        docker exec ecliptix_postgres pg_dump -U ecliptix_admin -d ecliptix_memberships > "$BACKUP_FILE"
        success "Backup created: $BACKUP_FILE"
        ;;

    restore)
        if [ -z "$ARG" ]; then
            error "Backup file required: ./dev-db.sh restore path/to/backup.sql"
            exit 1
        fi
        if [ ! -f "$ARG" ]; then
            error "Backup file not found: $ARG"
            exit 1
        fi
        warning "This will OVERWRITE the current database!"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            info "Restoring from: $ARG"
            cat "$ARG" | docker exec -i ecliptix_postgres psql -U ecliptix_admin -d ecliptix_memberships
            success "Database restored"
        else
            warning "Restore cancelled"
        fi
        ;;

    *)
        info "Ecliptix PostgreSQL Helper Script"
        info "Usage: ./dev-db.sh <command> [args]"
        echo ""
        info "Commands:"
        echo "  up         - Start PostgreSQL container"
        echo "  down       - Stop PostgreSQL container"
        echo "  restart    - Restart PostgreSQL"
        echo "  reset      - Drop & recreate database (DESTRUCTIVE)"
        echo "  migrate    - Apply pending migrations"
        echo "  new <name> - Create new migration"
        echo "  status     - Show migration & container status"
        echo "  logs       - Show PostgreSQL logs"
        echo "  psql       - Connect to PostgreSQL CLI"
        echo "  backup     - Create database backup"
        echo "  restore <file> - Restore from backup"
        ;;
esac
```

### Make Scripts Executable

```bash
chmod +x /Users/oleksandrmelnychenko/RiderProjects/Ecliptix/Scripts/dev-db.sh
chmod +x /Users/oleksandrmelnychenko/RiderProjects/Ecliptix/Scripts/dev-db.ps1
```

---

## ✅ Task 7: Verification

### Quick Start Commands

```bash
cd /Users/oleksandrmelnychenko/RiderProjects/Ecliptix

# 1. Start PostgreSQL
./Scripts/dev-db.sh up
# OR on Windows:
# .\Scripts\dev-db.ps1 up

# 2. Check status
./Scripts/dev-db.sh status

# 3. Create migration (if needed)
./Scripts/dev-db.sh new InitialPostgreSQLMigration

# 4. Apply migrations
./Scripts/dev-db.sh migrate

# 5. Verify in psql
./Scripts/dev-db.sh psql
# Inside psql:
\dt              # List tables
\d "Accounts"    # Describe table
SELECT COUNT(*) FROM "__EFMigrationsHistory";
\q               # Exit
```

---

## 🔧 Troubleshooting

### Issue: Container Won't Start

**Symptoms:**
```
Error: port 5432 already allocated
```

**Solution:**
```bash
# Check if PostgreSQL is running locally
lsof -i :5432

# If yes, stop it:
brew services stop postgresql
# OR
sudo systemctl stop postgresql

# Then retry:
docker-compose up -d
```

---

### Issue: Connection Refused

**Symptoms:**
```
Npgsql.NpgsqlException: Connection refused
```

**Solution:**
```bash
# 1. Check container is running
docker-compose ps

# 2. Check container logs
docker-compose logs postgres

# 3. Test connection directly
docker exec -it ecliptix_postgres pg_isready -U ecliptix_admin

# 4. Verify connection string in appsettings
cat Ecliptix.Core/appsettings.Development.Local.json
```

---

### Issue: Migration Fails - Column Type Mismatch

**Symptoms:**
```
The column 'RowVersion' cannot be configured as timestamp because the database provider doesn't support it
```

**Solution:**

PostgreSQL doesn't have `rowversion` like SQL Server. Update your configuration:

```csharp
// In EntityBaseMap.cs or specific entity configurations
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    foreach (var entityType in modelBuilder.Model.GetEntityTypes())
    {
        if (entityType.ClrType.IsAssignableTo(typeof(IConcurrent)))
        {
            var property = entityType.FindProperty(nameof(IConcurrent.RowVersion));
            if (property != null)
            {
                // For PostgreSQL: use xid type
                property.SetColumnType("xid");
                property.SetDefaultValueSql("pg_current_xact_id()");
                property.SetValueGeneratorFactory((p, e) => new TemporaryByteArrayValueGenerator());
            }
        }
    }
}
```

---

### Issue: Permission Denied on Scripts

**Symptoms:**
```
permission denied: ./Scripts/dev-db.sh
```

**Solution:**
```bash
chmod +x Scripts/dev-db.sh
chmod +x Scripts/dev-db.ps1
```

---

### Issue: Wrong Database Provider

**Symptoms:**
```
InvalidOperationException: No database provider has been configured
```

**Solution:**

Ensure `UsePostgreSQL` is set to `true` in appsettings.Development.Local.json:

```json
{
  "UsePostgreSQL": true,
  "ConnectionStrings": {
    "EcliptixMemberships": "Host=localhost;..."
  }
}
```

---

## 📚 Additional Resources

### PostgreSQL Commands Cheat Sheet

```sql
-- List all databases
\l

-- Connect to database
\c ecliptix_memberships

-- List all tables
\dt

-- Describe table structure
\d "Accounts"

-- List all schemas
\dn

-- Show current user
SELECT current_user;

-- Show all users
\du

-- Execute SQL file
\i path/to/file.sql

-- Show query execution time
\timing

-- Quit
\q
```

### Useful Docker Commands

```bash
# View container logs (follow mode)
docker-compose logs -f postgres

# Execute command in container
docker exec -it ecliptix_postgres bash

# Inspect container
docker inspect ecliptix_postgres

# View container stats
docker stats ecliptix_postgres

# Remove all containers and volumes (DESTRUCTIVE)
docker-compose down -v
```

---

## ✅ Next Steps

1. ✅ Docker setup complete
2. ✅ PostgreSQL running on localhost:5432
3. ✅ Connection string configured
4. ⏳ Install Npgsql packages
5. ⏳ Update Program.cs for PostgreSQL
6. ⏳ Create and apply migrations
7. ⏳ Test application with PostgreSQL

---

**Setup Status:** 🎯 Ready for Migration Creation

Use the helper scripts for easy database management:
```bash
./Scripts/dev-db.sh <command>
```

Available commands: `up`, `down`, `restart`, `reset`, `migrate`, `new`, `status`, `logs`, `psql`, `backup`, `restore`
