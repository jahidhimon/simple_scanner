"""Scanner for scanning for open ports in a url."""

import socket
import threading
from datetime import datetime
from termcolor import colored


class Scanner:
    """Scan all the port by vanilla method.

    Ports will be given as a list,
    if thread_c is not given default is 100.
    """

    def __init__(self, url: str, ports: list, thread_c=100):
        """Initialize the scanner class."""
        # Validation of arguments
        assert url != "", "Url cannot be empty."
        assert len(ports) > 0, "Ports list cannot be empty"
        assert thread_c > 0, "Thread count must be greater than 0"
        ip = socket.gethostbyname(url)
        assert ip != socket.herror, f"URL {url} is not valid"

        # Assign to self object
        self.__target_ip_addr = ip
        self.__target_url = url
        self.__ports = ports
        self.__p_scanned = 0
        self.__open_ports = []
        self.__start_time = datetime.now()
        self.__thread_count = thread_c

        # Printing Intro
        formatted_time = self.__start_time.strftime("%d/%m/%Y, %H:%M:%S")
        print(colored("-" * 50, 'green'))
        print(f"{colored('Scanning Target', 'yellow')}: {url} ", end="")
        print(f"({colored(ip, 'blue')})")
        print(f"{colored('Scanning started at', 'yellow')}: {formatted_time}")
        print(f"{colored('Total Ports', 'yellow')}: {len(ports)} ", end="")
        print(f"{colored('Threads Count', 'yellow')}: {thread_c}")
        print(colored("-" * 50, 'green'))
        self.print_status()

    def print_status(self):
        """Print the status of the scanner.

        Print how many ports scanned and how many ports found.
        Also print the time of the scan
        """
        op_str = f"Open Ports Found: {len(self.__open_ports)}"
        sp_str = f"Scanned Ports: {self.__p_scanned}"
        now = datetime.now()
        dur = (now - self.__start_time).total_seconds()
        dur_str = f"Elapsed time: {int(dur)} sec"

        print(f"\r{op_str}, {sp_str}, {dur_str}", end="")

    @classmethod
    def read_ports_from_file(cls, filename):
        r"""Read and return a list from filename, seperated by ' ' or '\n'."""
        ports = []
        with open(filename, 'r') as f:
            data = f.read()
            ports = data.split()
        return [int(x) for x in ports]

    def __port_scanner(self, port):
        """Scan a specific port.

        If the port is connectable the function returns True.
        If the hostname could not be resolved it throws socket.gaierror
        If the server does not respond it throws socket.error
        """
        try:
            self.__p_scanned += 1
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((self.__target_url, port)) == 0:
                s.close()
                return True
            s.close()

        except socket.gaierror:
            print("\nHostname Could not be Resolved!!!")
        except socket.error:
            print("\nServer not responding!!!")

    def __list_scanner(self, lst):
        """Scan a range of port using self.__port_scanner method."""
        for p in lst:
            if self.__port_scanner(p):
                self.__open_ports.append(p)
            self.print_status()

    def scan(self):
        """Scan the list __ports."""
        threads = []
        part_size = int(len(self.__ports) / self.__thread_count)
        for it in range(0, self.__thread_count):
            start = it * part_size
            r = self.__ports[start:(start+part_size)]
            thread = threading.Thread(target=self.__list_scanner, args=[r])
            thread.start()
            threads.append(thread)

        rem = len(self.__ports) - (self.__thread_count * part_size)
        if rem != 0:
            r = self.__ports[-rem:]
            thread = threading.Thread(target=self.__list_scanner, args=[r])
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join(timeout=70)
        print()
        print(*self.__open_ports, sep="\n")
