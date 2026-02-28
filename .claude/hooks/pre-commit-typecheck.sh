#!/bin/bash
INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command')

if echo "$COMMAND" | grep -q "git commit"; then
  cd "$CLAUDE_PROJECT_DIR"
  if ! pnpm typecheck 2>&1; then
    echo "Blocked: pnpm typecheck failed. Fix type errors before committing." >&2
    exit 2
  fi
fi
exit 0
