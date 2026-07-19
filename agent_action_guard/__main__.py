"""Module entry point for `python -m agent_action_guard` (ADR-0001 N34)."""

import sys

from agent_action_guard.cli import main

if __name__ == "__main__":
    sys.exit(main())
