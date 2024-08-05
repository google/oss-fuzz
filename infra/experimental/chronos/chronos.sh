# Usage:
# 1. Set FUZZ_TARGET (e.g., in Dockerfile)
# 2. Source this file before compiling the fuzz target (source chronos.sh).

export START_RECORDING="false"
RECOMPILE_ENV="/usr/local/bin/recompile_env.sh"


# Initialize the recompile script.
initialize_recompile_script() {
    export RECOMPILE_SCRIPT="/usr/local/bin/recompile"
    echo "#!/bin/bash" > "$RECOMPILE_SCRIPT"
    echo "source $RECOMPILE_ENV" >> "$RECOMPILE_SCRIPT" 
    chmod +x "$RECOMPILE_SCRIPT" 
}


# Execute or record command for recompilation.
execute_or_record_command() {
    record_command() {
        echo "cd \"$(pwd)\"" >> "$RECOMPILE_SCRIPT"
        echo "$@" >> "$RECOMPILE_SCRIPT"
    }

    # Check if any element in the command array contains the FUZZ_TARGET.
   if [[ "$BASH_COMMAND" == *"$FUZZ_TARGET"* ]]; then
       export START_RECORDING="true"
       # Save all environment variables, excluding read-only ones
       declare -p | grep -Ev 'declare -[^ ]*r[^ ]*' > "$RECOMPILE_ENV"
   fi

    if [[ "$START_RECORDING" == "true" ]]; then
        record_command "$BASH_COMMAND"
        echo "Simulated (logged) execution of: $BASH_COMMAND"
    fi
}


main() {
    # Initialize.
    initialize_recompile_script
    
    # Set up trap for DEBUG to intercept commands.
    trap 'execute_or_record_command' DEBUG

    # Enable extended debugging mode
    shopt -s extdebug  
    # Ensure trap works in subshells and functions.
    set -T  
}

main
