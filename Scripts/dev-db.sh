#!/bin/bash
# Ecliptix PostgreSQL Development Database Helper Script

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOMAIN_PROJECT="$PROJECT_ROOT/src/Contexts/IdentityAccess/Infrastructure/Ecliptix.IdentityAccess.Infrastructure.csproj"
STARTUP_PROJECT="$PROJECT_ROOT/Ecliptix.Core/Ecliptix.Core.csproj"
BACKUP_DIR="$PROJECT_ROOT/Backups"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

success() { echo -e "${GREEN}✅ $1${NC}"; }
info() { echo -e "${CYAN}ℹ️  $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

CMD="${1:-status}"
ARG="${2}"

cd "$PROJECT_ROOT" || exit 1

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
            dotnet ef database update --project "$DOMAIN_PROJECT" --startup-project "$STARTUP_PROJECT" --context EcliptixSchemaContext
            success "Database reset complete!"
        else
            warning "Reset cancelled"
        fi
        ;;
    migrate)
        info "Applying pending migrations..."
        dotnet ef database update --project "$DOMAIN_PROJECT" --startup-project "$STARTUP_PROJECT" --context EcliptixSchemaContext
        success "Migrations applied"
        ;;
    new)
        if [ -z "$ARG" ]; then
            error "Migration name required: ./dev-db.sh new MigrationName"
            exit 1
        fi
        info "Creating new migration: $ARG"
        dotnet ef migrations add "$ARG" --project "$DOMAIN_PROJECT" --startup-project "$STARTUP_PROJECT" --context EcliptixSchemaContext --output-dir Migrations/PostgreSQL
        success "Migration created: $ARG"
        ;;
    status)
        info "Migration Status:"
        dotnet ef migrations list --project "$DOMAIN_PROJECT" --startup-project "$STARTUP_PROJECT" --context EcliptixSchemaContext
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
