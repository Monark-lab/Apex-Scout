import validators
from urllib.parse import urlparse
import socket

BLOCkED_HOSTS = ["localhost", "127.0.0.1"]


def is_valid_target(url):
    if not validators.url(url):
        return False
    
    parsed = urlparse(url)
    hostname = parsed.hostname

    if hostname in BLOCkED_HOSTS:
        return False
    
    try:
        ip = socket.gethostbyname(hostname)
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            return False
        
    except:
        return False

    return True