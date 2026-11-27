"""`python3 -m repobeagle` entrypoint."""
import sys

# --- cross-module imports ---

from .cli import main


if __name__ == "__main__":
    sys.exit(main())