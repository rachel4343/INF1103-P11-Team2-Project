## io_helpers.py under io_manager.py
"""Pure utility functions used by I/O classes."""

def clean(text: str) -> str:
    return "".join(c for c in str(text) if c.isprintable() or c == "\n").strip()


def short(value, length=45) -> str:
    value = str(value if value is not None else "")
    return value if len(value) <= length else value[:length - 3] + "..."

