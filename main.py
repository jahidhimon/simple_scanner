"""Main file for the Vulnerability checker."""

from scanner import Scanner

if __name__ == "__main__":
    ports = Scanner.read_ports_from_file("ports.txt")
    scanner = Scanner("www.google.com", ports, thread_c=20)
    scanner.scan()
