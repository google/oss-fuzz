# Usage: Source this file at the beginning or at least before the fuzz target compilation command:
# source chronos.sh

# Initialize re-run.sh
echo "#!/bin/bash" > re-run.sh
echo "source /src/saved_vars.sh" >> re-run.sh
chmod +x re-run.sh

export FUZZ_TARGET="fuzz_mms_decode.c"
export LOGGING="false"

# Logging Function
log_command() {
    local cmd="$@"
    local log_file="$SRC/re-run.sh"
    local current_dir=$(pwd)
    echo "cd \"$current_dir\"" >> $log_file
    echo "$cmd" >> $log_file
}

# Command Execution and Logging Function
execute_or_log_command() {
    local cmd="$BASH_COMMAND"
    if [[ "$cmd" == *"$FUZZ_TARGET"* ]]; then
        declare -p > /src/saved_vars.sh
        log_command "$cmd"
        echo "Simulated (logged) execution of: $cmd"
        export LOGGING="true"
        # kill -SIGINT $$  # Skip execution of subsequent commands
        BASH_COMMAND=":"  # Override the command with a no-op
    elif [ "$LOGGING" = "true" ]; then
        log_command "$cmd"
        echo "Simulated (logged) execution of: $cmd"
        # kill -SIGINT $$  # Skip execution of subsequent commands
        BASH_COMMAND=":"  # Override the command with a no-op
    fi
}

# Set up trap for DEBUG to intercept commands
trap 'execute_or_log_command' DEBUG
shopt -s extdebug
set -T  # Ensure trap works in subshells and functions
