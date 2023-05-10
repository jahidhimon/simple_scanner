"""Main file for the Vulnerability checker."""

from scanner import Scanner
from ssl_checker import ssl_valid_time_remaining

if __name__ == "__main__":
    ports = Scanner.read_ports_from_file("ports.txt")
    scanner = Scanner("www.google.com", ports, thread_c=10, verbose=True)
    scanner.scan()
    ssl_valid_time_remaining("www.google.com")
