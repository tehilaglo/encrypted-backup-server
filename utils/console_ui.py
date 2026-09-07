"""
Console styling utilities for the encrypted backup server.

This module defines ANSI escape-code constants used to color and format
terminal output printed by the server.

@author Tehila Cahnaman
"""


class Color:
    """
    ANSI escape-code constants for styling console output.

    These constants can be used when printing status, success, warning, or
    error messages to the terminal.
    """

    #: Red text, typically used for errors.
    RED: str = "\033[91m"

    #: Green text, typically used for success or active server status messages.
    GREEN: str = "\033[92m"

    #: Yellow text, typically used for warnings.
    YELLOW: str = "\033[93m"

    #: Blue text, typically used for informational success messages.
    BLUE: str = "\033[94m"

    #: Purple text, available for secondary highlighted messages.
    PURPLE: str = "\033[95m"

    #: Cyan text, available for informational messages.
    CYAN: str = "\033[96m"

    #: Bold text formatting.
    BOLD: str = "\033[1m"

    #: Underlined text formatting.
    UNDERLINE: str = "\033[4m"

    #: Reset all text color and formatting styles.
    RESET: str = "\033[0m"
