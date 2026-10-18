#!/bin/bash
#
# tblocker - live log viewer
#
# Supports both old (/usr/local/x-ui) and new (/var/log/x-ui) x-ui log
# locations, the tblocker service journal, and custom log paths.
#
# Installed to /opt/tblocker/logs.sh and linked as /usr/local/bin/tblocker-logs
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

OLD_LOG="/usr/local/x-ui/access.log"
NEW_LOG="/var/log/x-ui/access.log"
SERVICE_NAME="tblocker"

# Pressing Ctrl+C while following a log returns to the menu instead of exiting
trap 'echo ""' INT

print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

follow_file() {
    local path="$1"

    if [ ! -f "$path" ]; then
        print_warning "Log file does not exist: $path"
        read -p "Do you want to create it and follow? (y/N): " create_it
        if [[ $create_it =~ ^[Yy]$ ]]; then
            mkdir -p "$(dirname "$path")"
            touch "$path"
        else
            return
        fi
    fi

    print_info "Following $path (press Ctrl+C to return to the menu)"
    tail -f "$path"
}

follow_journal() {
    print_info "Following $SERVICE_NAME service log (press Ctrl+C to return to the menu)"
    journalctl -u "$SERVICE_NAME" -f
}

detect_log() {
    if [ -f "$NEW_LOG" ]; then
        echo "$NEW_LOG"
    elif [ -f "$OLD_LOG" ]; then
        echo "$OLD_LOG"
    else
        echo ""
    fi
}

while true; do
    detected="$(detect_log)"

    echo ""
    echo "==============================================="
    echo "             tblocker - live logs              "
    echo "==============================================="
    if [ -n "$detected" ]; then
        print_success "x-ui log detected at: $detected"
    else
        print_warning "No x-ui access log found on this system"
    fi
    echo ""
    echo "1) x-ui access log - OLD path ($OLD_LOG)"
    echo "2) x-ui access log - NEW path ($NEW_LOG)"
    echo "3) x-ui access log - auto-detect (recommended)"
    echo "4) tblocker service log (journalctl -u $SERVICE_NAME -f)"
    echo "5) Custom log path"
    echo "0) Exit"
    echo ""
    read -p "Select an option: " choice

    case $choice in
        1)
            follow_file "$OLD_LOG"
            ;;
        2)
            follow_file "$NEW_LOG"
            ;;
        3)
            if [ -n "$detected" ]; then
                follow_file "$detected"
            else
                print_warning "Nothing to auto-detect. Choose option 5 and enter a path."
            fi
            ;;
        4)
            follow_journal
            ;;
        5)
            read -p "Enter log file path: " custom_path
            if [ -n "$custom_path" ]; then
                follow_file "$custom_path"
            fi
            ;;
        0)
            exit 0
            ;;
        *)
            print_warning "Invalid option. Please try again."
            ;;
    esac
done
