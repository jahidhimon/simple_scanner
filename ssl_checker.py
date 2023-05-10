"""Simply checks ssl certificate of an url."""

import socket
import ssl
from datetime import datetime
from termcolor import colored


def __ssl_expiry_datetime(hostname):
    """Return ssl certificate expiration date."""
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    # parse the string from the certificate into a Python datetime object
    return datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)


def ssl_valid_time_remaining(hostname):
    """Get the number of days left in a cert's lifetime.

    - Return values
    Returns the difference between two datetime objects.
    Current Day and the Expiry Day.
    """
    expires = __ssl_expiry_datetime(hostname)
    str_fmt = f"SSL cert for {hostname} expires at {expires}"
    print(colored(str_fmt, 'yellow'))
    return expires - datetime.utcnow()
