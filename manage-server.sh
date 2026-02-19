#!/bin/bash

# Ecliptix Server Management Script
# Usage: ./manage-server.sh {start|stop|restart|status|logs}

PROJECT_DIR="/Users/oleksandrmelnychenko/RiderProjects/Ecliptix/Ecliptix.Core"
LOG_DIR="/Users/oleksandrmelnychenko/RiderProjects/Ecliptix/logs"
LOG_FILE="$LOG_DIR/server.log"
PID_FILE="$LOG_DIR/server.pid"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function start() {
    echo -e "${YELLOW}Starting Ecliptix server...${NC}"

    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            echo -e "${RED}Server is already running (PID: $PID)${NC}"
            return 1
        else
            echo -e "${YELLOW}Removing stale PID file...${NC}"
            rm "$PID_FILE"
        fi
    fi

    # Create log directory if it doesn't exist
    mkdir -p "$LOG_DIR"

    # Start server in background
    cd "$PROJECT_DIR" && nohup dotnet run > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    echo "$SERVER_PID" > "$PID_FILE"

    # Wait a bit and check if it's running
    sleep 3
    if ps -p "$SERVER_PID" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Server started successfully (PID: $SERVER_PID)${NC}"
        echo -e "${GREEN}✓ Server is listening on http://localhost:5051${NC}"
        echo -e "${YELLOW}  View logs: ./manage-server.sh logs${NC}"
        return 0
    else
        echo -e "${RED}✗ Server failed to start. Check logs: $LOG_FILE${NC}"
        rm "$PID_FILE"
        return 1
    fi
}

function stop() {
    echo -e "${YELLOW}Stopping Ecliptix server...${NC}"

    if [ ! -f "$PID_FILE" ]; then
        echo -e "${RED}PID file not found. Searching for running processes...${NC}"
        PIDS=$(pgrep -f "dotnet.*Ecliptix.Core")
        if [ -z "$PIDS" ]; then
            echo -e "${YELLOW}No running server found${NC}"
            return 1
        else
            echo -e "${YELLOW}Found running server(s), stopping...${NC}"
            kill $PIDS
            echo -e "${GREEN}✓ Server stopped${NC}"
            return 0
        fi
    fi

    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        kill "$PID"
        sleep 2

        # Force kill if still running
        if ps -p "$PID" > /dev/null 2>&1; then
            echo -e "${YELLOW}Force killing server...${NC}"
            kill -9 "$PID"
        fi

        rm "$PID_FILE"
        echo -e "${GREEN}✓ Server stopped${NC}"
    else
        echo -e "${YELLOW}Server is not running${NC}"
        rm "$PID_FILE"
    fi
}

function restart() {
    echo -e "${YELLOW}Restarting Ecliptix server...${NC}"
    stop
    sleep 2
    start
}

function status() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p "$PID" > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Server is running (PID: $PID)${NC}"
            echo -e "${GREEN}✓ Listening on port 5051${NC}"

            # Check if port is actually listening
            if lsof -i :5051 -P -n | grep LISTEN > /dev/null 2>&1; then
                echo -e "${GREEN}✓ Port 5051 is LISTENING${NC}"
            else
                echo -e "${YELLOW}⚠ Process running but port 5051 not listening${NC}"
            fi
            return 0
        else
            echo -e "${RED}✗ Server is not running (stale PID file)${NC}"
            rm "$PID_FILE"
            return 1
        fi
    else
        # Check if server is running without PID file
        PIDS=$(pgrep -f "dotnet.*Ecliptix.Core")
        if [ -n "$PIDS" ]; then
            echo -e "${YELLOW}⚠ Server is running but PID file is missing${NC}"
            echo -e "${YELLOW}  PID(s): $PIDS${NC}"
            echo "$PIDS" | head -1 > "$PID_FILE"
            return 0
        else
            echo -e "${RED}✗ Server is not running${NC}"
            return 1
        fi
    fi
}

function logs() {
    if [ -f "$LOG_FILE" ]; then
        echo -e "${YELLOW}Tailing server logs (Ctrl+C to exit)...${NC}"
        tail -f "$LOG_FILE"
    else
        echo -e "${RED}Log file not found: $LOG_FILE${NC}"
        return 1
    fi
}

# Main script
case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the Ecliptix server"
        echo "  stop    - Stop the Ecliptix server"
        echo "  restart - Restart the Ecliptix server"
        echo "  status  - Check server status"
        echo "  logs    - Tail server logs"
        exit 1
        ;;
esac
