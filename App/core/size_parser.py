# App/core/size_parser.py
"""Parse human-readable size strings like '1MB', '512KB', '2GB' to bytes."""

import re
from typing import Union

_UNITS = {
    "B": 1,
    "KB": 1024,
    "MB": 1024 ** 2,
    "GB": 1024 ** 3,
    "TB": 1024 ** 4,
    "KIB": 1024,
    "MIB": 1024 ** 2,
    "GIB": 1024 ** 3,
    "TIB": 1024 ** 4,
}

_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]+)?\s*$")


def parse_size(value: Union[str, int]) -> int:
    """
    Parse '1MB', '512KB', '2.5GB', '1024' → bytes (int).

    Examples:
        parse_size("1MB")     → 1048576
        parse_size("512KB")   → 524288
        parse_size("2GB")     → 2147483648
        parse_size("1024")    → 1024
        parse_size(1024)      → 1024
    """
    if isinstance(value, int):
        if value <= 0:
            raise ValueError(f"Size must be positive, got {value}")
        return value

    match = _PATTERN.match(str(value))
    if not match:
        raise ValueError(f"Invalid size format: '{value}'. Use e.g. '1MB', '512KB', '2GB'")

    number_str, unit_str = match.groups()
    number = float(number_str)

    if unit_str is None:
        unit = "B"
    else:
        unit = unit_str.upper()
        if unit not in _UNITS:
            raise ValueError(
                f"Unknown unit '{unit_str}' in '{value}'. "
                f"Valid units: {', '.join(sorted(_UNITS.keys()))}"
            )

    result = int(number * _UNITS[unit])
    if result <= 0:
        raise ValueError(f"Size must be positive, got '{value}'")

    return result


def format_size(bytes_count: int) -> str:
    """
    Human-readable size from bytes.
    Examples:
        format_size(1048576)      → "1 MB"
        format_size(524288)       → "512 KB"
        format_size(1500)         → "1.46 KB"
    """
    if bytes_count < 1024:
        return f"{bytes_count} B"

    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(bytes_count)
    for i, unit in enumerate(units):
        if size < 1024:
            return f"{size:.2f} {unit}".rstrip("0").rstrip(".")
        size /= 1024
    return f"{size:.2f} PB"