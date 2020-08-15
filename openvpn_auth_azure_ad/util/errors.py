class AuthenticatorError(Exception):
    """Base exception for all other project exceptions."""


class NotConnectedError(AuthenticatorError):
    """Exception raised if not connected to the management interface and a command is called."""


class ConnectError(AuthenticatorError):
    """Exception raised on connection failure."""


class ParseError(AuthenticatorError):
    """Exception raised on parse error."""
