"""Out-of-band (OOB) callback receiver.

Detects blind vulnerabilities (blind SQLi, SSRF, XXE, log4shell,
command injection without output, stored XSS that fires later) by
running a server that records every HTTP request it gets and
correlating those callbacks back to the payloads that triggered them.

Architecture: the agent embeds a unique token in each blind-style
payload (``http://abc123.callback.example/probe``). When the target
backend processes the payload, it issues a request to our server.
The server logs the request; the scanner polls and matches the
token to the original payload, turning a silent backend into a
confirmed-with-confidence-1.0 finding.

This is the same shape as Burp Collaborator and projectdiscovery
Interactsh.
"""

from bounty_agent.oob.server import CallbackEvent, CallbackLog, OobServer
from bounty_agent.oob.tokens import OobToken, TokenRegistry, generate_token

__all__ = [
    "CallbackEvent",
    "CallbackLog",
    "OobServer",
    "OobToken",
    "TokenRegistry",
    "generate_token",
]
