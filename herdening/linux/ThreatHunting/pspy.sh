#!/bin/bash
# pspy_interactive_filter.sh
# This script runs pspy and lets you add script names to filter out.
# Instead of filtering by PID, it filters based on a script name contained in the output,
# and automatically skips lines that look like internal pspy parsing spam or have an empty command.

# Define the pspy binary location and download URL.
PSPY_BIN="./pspy64"
PSPY_URL="https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64"

# Check if pspy exists and is executable; if not, download it.
if [ ! -x "$PSPY_BIN" ]; then
    echo "pspy64 not found or not executable. Downloading from $PSPY_URL..."
    if command -v wget >/dev/null 2>&1; then
        wget "$PSPY_URL" -O "$PSPY_BIN"
    elif command -v curl >/dev/null 2>&1; then
        curl -L "$PSPY_URL" -o "$PSPY_BIN"
    else
        echo "Error: neither wget nor curl is installed. Please install one to download pspy64."
        exit 1
    fi
    chmod +x "$PSPY_BIN"
    if [ ! -x "$PSPY_BIN" ]; then
        echo "Failed to download or set execute permissions on $PSPY_BIN."
        exit 1
    fi
fi

# Create a temporary file to store the script names to filter.
FILTER_FILE=$(mktemp)
# Create a FIFO (named pipe) for capturing pspy's output.
FIFO=$(mktemp -u)
mkfifo "$FIFO"

# Clean up temporary files on exit.
trap "rm -f $FILTER_FILE '$FIFO'" EXIT

# Start pspy, writing its output to the FIFO.
"$PSPY_BIN" > "$FIFO" &
pspy_pid=$!
echo "Started pspy (PID $pspy_pid)."
echo "Press any key to pause and add a script name to filter."
echo "Press Enter (with no input) to resume, or type 'exit' to quit."

# Open the FIFO for reading on file descriptor 3.
exec 3<"$FIFO"

# Main loop: read from pspy output and check for user input.
while true; do
  # Check for a keypress on /dev/tty without blocking.
  if read -t 0.1 -n 1 key < /dev/tty 2>/dev/null; then
    # Pause pspy so its output stops.
    kill -STOP "$pspy_pid"
    
    # Prompt the user directly for a script name to filter.
    echo -ne "\n--- PAUSED ---\nEnter script name to filter (press Enter to resume, or type 'exit' to quit): " > /dev/tty
    read -e -r input < /dev/tty

    if [[ "$input" == "exit" ]]; then
      echo "Exiting and terminating pspy." > /dev/tty
      kill "$pspy_pid"
      break
    fi

    # If something was entered, add it to the filter list.
    if [[ -n "$input" ]]; then
      echo "$input" >> "$FILTER_FILE"
      echo "Added script name '$input' to filter list." > /dev/tty
    fi

    # Resume pspy.
    kill -CONT "$pspy_pid"
  fi

  # Read a line from the FIFO (with a short timeout).
  if read -t 0.1 -r line <&3; then
    skip=0

    # Expanded automatic filtering:
    # Skip lines that are blank, have an empty command (nothing after the pipe),
    # or appear to be part of pspy's internal parsing spam.
    if [[ "$line" =~ ^[[:space:]]*$ ]] || \
       [[ "$line" =~ \|[[:space:]]*$ ]] || \
       [[ "$line" =~ ^\(\( ]] || [[ "$line" =~ ^END ]] || \
       [[ "$line" =~ "awk -v pane_pid" ]] || [[ "$line" =~ "child[" ]] || [[ "$line" =~ "command[" ]] || \
       [[ "$line" =~ ^[[:space:]]*\}[[:space:]]*$ ]] || [[ "$line" =~ ^pid\ =\ pane_pid ]] || \
       [[ "$line" =~ ^break$ ]]; then
      skip=1
    fi

    # If not already skipped, check for any user-specified script names.
    if [ $skip -eq 0 ] && [ -s "$FILTER_FILE" ]; then
      while IFS= read -r filter_script; do
        if [[ "$line" == *"$filter_script"* ]]; then
          skip=1
          break
        fi
      done < "$FILTER_FILE"
    fi

    # Output the line only if not filtered.
    if [ $skip -eq 0 ]; then
      echo "$line"
    fi
  fi
done
