#!/bin/bash
# inotify_interactive_filter_selected.sh
# Monitors file events in /etc, /home, /var, /tmp.
# Interactively manages regex filters via dialog.
# Checks for insufficient watchers and prints an error if so.
# Properly handles "Unknown (deleted)" user_id without numeric comparisons.

# -------------------------------
# Check for inotifywait and install inotify-tools if missing
# -------------------------------
if ! command -v inotifywait &> /dev/null; then
    echo "inotifywait not found. Attempting to install inotify-tools..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y inotify-tools
    elif command -v yum &> /dev/null; then
        sudo yum install -y inotify-tools
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y inotify-tools
    else
        echo "No supported package manager found. Please install inotify-tools manually."
        exit 1
    fi
fi

# -------------------------------
# Check for dialog and install it if missing
# -------------------------------
if ! command -v dialog &> /dev/null; then
    echo "dialog not found. Attempting to install dialog..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y dialog
    elif command -v yum &> /dev/null; then
        sudo yum install -y dialog
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y dialog
    else
        echo "No supported package manager found. Please install dialog manually."
        exit 1
    fi
fi

# -------------------------------
# Adjust fs.inotify.max_user_watches based on available memory
# (Using increased limits)
# -------------------------------
TOTAL_MEM=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_MB=$((TOTAL_MEM / 1024))

if [ "$TOTAL_MEM_MB" -lt 4000 ]; then
    MAX_WATCHES=262144
elif [ "$TOTAL_MEM_MB" -lt 8000 ]; then
    MAX_WATCHES=1048576
else
    MAX_WATCHES=2097152
fi

echo "Setting fs.inotify.max_user_watches to $MAX_WATCHES based on system memory..."
sudo sysctl -w fs.inotify.max_user_watches=$MAX_WATCHES

# -------------------------------
# Define Colors for output
# -------------------------------
RED="\033[1;31m"      # For UID 0 (root)
GREEN="\033[1;32m"    # For UID 1-999
YELLOW="\033[1;33m"   # For UID 1000+
BLUE="\033[1;34m"     # For timestamps/general text
CYAN="\033[1;36m"     # For banner
RESET="\033[0m"       # Reset color

# -------------------------------
# Banner and Basic Info
# -------------------------------
echo -e "${GREEN}"
echo "******************************************************"
echo "*     Inotify Interactive Monitor (/etc /home /var /tmp)    *"
echo "******************************************************"
echo -e "${RESET}"
echo -e "${CYAN}Monitoring file events in /etc, /home, /var, and /tmp.${RESET}"
echo -e "Color coding by UID:"
echo -e "${RED}  UID 0 -> RED${RESET}"
echo -e "${GREEN}  UID 1-999 -> GREEN${RESET}"
echo -e "${YELLOW}  UID 1000+ -> YELLOW${RESET}"
echo -e "${BLUE}Timestamps in blue.${RESET}"
echo ""
echo "Monitor is running. Press any key to update filter patterns."
echo "Type 'exit' in the filter prompt to quit."
echo ""

# -------------------------------
# Define the directories to watch
# -------------------------------
WATCH_DIRS="/etc /home /var /tmp"

# -------------------------------
# Setup temporary filter file
# -------------------------------
FILTER_FILE=$(mktemp /tmp/inotify_filter.XXXX)
: > "$FILTER_FILE"  # Start empty

# We'll maintain a combined filter variable.
combined_filter=""

# -------------------------------
# Create FIFO for inotify output (in /run so it's not being watched).
# -------------------------------
FIFO=$(mktemp -u /run/inotify_fifo.XXXX)
mkfifo "$FIFO"

# Ensure cleanup on exit.
cleanup() {
    rm -f "$FILTER_FILE" "$FIFO"
}
trap cleanup EXIT

# -------------------------------
# Start inotifywait in the background,
# capturing errors to a temp file so we can detect if it fails to start.
# -------------------------------
inotify_err=$(mktemp /tmp/inotify_err.XXXX)

sudo inotifywait -m -r -e create -e modify -e delete \
     $WATCH_DIRS \
     --format '%w%f %e' \
     > "$FIFO" 2> "$inotify_err" &

MONITOR_PID=$!

# Give inotifywait a brief moment to fail if it can't set all watchers
sleep 2

# Check if inotifywait is still running
if ! kill -0 "$MONITOR_PID" 2>/dev/null; then
    echo -e "${RED}Error: inotifywait terminated early, likely due to insufficient inotify watches.${RESET}"
    echo -e "Details from stderr:"
    cat "$inotify_err"
    rm -f "$inotify_err"
    exit 1
fi

# If we get here, inotifywait is presumably running fine
rm -f "$inotify_err"

# -------------------------------
# Open the FIFO for reading on file descriptor 3.
# -------------------------------
exec 3<"$FIFO"

# -------------------------------
# Function: Update combined filter variable
# -------------------------------
update_combined_filter() {
  if [ -s "$FILTER_FILE" ]; then
    combined_filter=$(grep -v '^[[:space:]]*$' "$FILTER_FILE" | paste -sd '|' -)
  else
    combined_filter=""
  fi
}

# Initial update.
update_combined_filter

# -------------------------------
# Main loop: Process FIFO output and check for interactive filter update.
# -------------------------------
while true; do
    # Check for keypress on /dev/tty (non-blocking).
    if read -t 0.1 -n 1 key < /dev/tty; then
         # Drain any pending FIFO output to reduce backlog.
         while read -t 0.01 -r junk <&3; do :; done

         # Pause the monitor process.
         kill -STOP "$MONITOR_PID"

         # Clear the screen to minimize interference.
         clear

         # Use dialog for interactive input.
         new_filter=$(dialog --clear --title "Filter Input" \
            --inputbox "Enter new filter pattern (regex) to ignore events (or type 'exit' to quit):" \
            10 60 \
            3>&1 1>&2 2>&3 3>&-)

         retval=$?
         clear

         # If the user pressed 'Cancel' or typed 'exit', quit the script
         if [ $retval -ne 0 ] || [ "$new_filter" == "exit" ]; then
             echo "Exiting monitoring..."
             kill "$MONITOR_PID"
             break
         fi

         # If the user typed something non-empty, add it to the filter list
         if [ -n "$new_filter" ]; then
             echo "$new_filter" >> "$FILTER_FILE"
             echo "Added filter pattern: '$new_filter'"
             update_combined_filter
         else
             echo "No filter pattern entered; continuing..."
         fi

         # Resume the monitor.
         kill -CONT "$MONITOR_PID"
    fi

    # Process lines from FIFO.
    if read -t 0.1 -r line <&3; then
         # If the combined filter is non-empty and the event matches it, ignore it
         if [ -n "$combined_filter" ] && echo "$line" | grep --line-buffered -q -E "$combined_filter"; then
             continue
         fi

         file=$(echo "$line" | awk '{print $1}')
         event=$(echo "$line" | awk '{print $2}')

         # Determine user_id and username
         if [[ "$event" != "DELETE" && -e "$file" ]]; then
             user_id=$(stat -c '%u' "$file" 2>/dev/null)
             username=$(stat -c '%U' "$file" 2>/dev/null)
         elif [[ "$event" == "DELETE" ]]; then
             user_id="Unknown (deleted)"
             username="Unknown"
         else
             user_id="Unknown"
             username="Unknown"
         fi

         # ------------------------------------------------------
         # Color-coding by user_id, ensuring no numeric comparisons
         # on "Unknown (deleted)"
         # ------------------------------------------------------
         if [[ "$user_id" =~ ^[0-9]+$ ]]; then
             # It's numeric, do numeric comparisons
             if [[ "$user_id" -eq 0 ]]; then
                 color=$RED
             elif [[ "$user_id" -ge 1000 ]]; then
                 color=$YELLOW
             elif [[ "$user_id" -ge 1 && "$user_id" -le 999 ]]; then
                 color=$GREEN
             else
                 color=$BLUE
             fi
         else
             # It's "Unknown" or "Unknown (deleted)" or something else non-numeric
             color=$BLUE
         fi

         # Print the event
         if [[ "$user_id" == "Unknown" || "$user_id" == "Unknown (deleted)" ]]; then
             # Just print in blue with the Unknown user
             echo -e "${BLUE}$(date '+[%Y-%m-%d %H:%M:%S]')${RESET} $line [UID: $user_id ($username)]"
         else
             # For numeric user_id, keep the color formatting on the event line
             echo -e "${BLUE}$(date '+[%Y-%m-%d %H:%M:%S]')${RESET} $color$line${RESET} [${color}UID: $user_id ($username)${RESET}]"
         fi
    fi
done
