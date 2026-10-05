"""Origin-bound HTTP requests for host-side acceptance clients."""

import socket
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urlopen(url, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, *, context=None):
    """Return the configured origin's response; expose redirects as HTTPError.

    urllib's default redirect handler forwards bearer credentials across origins
    and can turn a failed probe into a successful response from another server.
    Keep the caller's TLS context and the standard proxy/HTTP error behavior.
    """
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=context)
    )
    return opener.open(url, data=data, timeout=timeout)
