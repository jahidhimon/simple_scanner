"""Scanner for scanning for open ports in a url."""

import socket
import threading
import re
from dataclasses import dataclass
from datetime import datetime
from termcolor import colored


class Scanner:
    """Scan ports of ports by using many threads.

    Ports will be given as a list,
    if thread_c is not given default is 100.
    """

    def __init__(self, url: str, ports: list, thread_c=100, verbose=True):
        """Initialize the scanner class."""
        # Validation of arguments
        assert url != "", "Url cannot be empty."
        assert len(ports) > 0, "Ports list cannot be empty"
        assert thread_c > 0, "Thread count must be greater than 0"
        ip = socket.gethostbyname(url)
        assert ip != socket.herror, f"URL {url} is not valid"

        # Assign to self object
        self.__verbose = verbose
        self.__target_ip_addr = ip
        self.__target_url = url
        self.__ports = ports
        self.__p_scanned = 0
        self._open_ports = []
        self.__start_time = datetime.now()
        self.__thread_count = thread_c

        if self.__verbose:
            self.scanner_intro_info()

    def scanner_intro_info(self):
        """Print Intro of Scanner instance."""
        formatted_time = self.__start_time.strftime("%d/%m/%Y, %H:%M:%S")
        print(colored("-" * 50, 'green'))
        init_info = (
            f"{colored('Scanning Target', 'yellow')}: {self.__target_url} "
            f"({colored(self.__target_ip_addr, 'blue')})\n"
            f"{colored('Scanning started at', 'yellow')}: {formatted_time}\n"
            f"{colored('Total Ports', 'yellow')}: {len(self.__ports)} "
            f"{colored('Threads Count', 'yellow')}: {self.__thread_count}"
        )
        print(init_info)
        print(colored("-" * 50, 'green'))
        self.print_status()

    def print_status(self) -> None:
        """Print the status of the scanner.

        Print how many ports scanned and how many ports found.
        Also print the time of the scan
        """
        op_str = f"Open Ports Found: {len(self._open_ports)}"
        sp_str = f"Scanned Ports: {self.__p_scanned}"
        now = datetime.now()
        dur = (now - self.__start_time).total_seconds()
        dur_str = f"Elapsed time: {int(dur)} sec"

        print(f"\r{op_str}, {sp_str}, {dur_str}", end="")

    @classmethod
    def read_ports_from_file(cls, filename: str) -> list[int]:
        r"""Read and return a list from filename, seperated by ' ' or '\n'."""
        ports = []
        with open(filename, 'r') as f:
            data = f.read()
            ports = data.split()
        return [int(x) for x in ports]

    def __port_scanner(self, port: int) -> bool:
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

    def __list_scanner(self, lst: list[int]) -> None:
        """Scan a range of port using self.__port_scanner method."""
        for p in lst:
            if self.__port_scanner(p):
                self._open_ports.append(p)
            if self.__verbose:
                self.print_status()

    def scan(self) -> None:
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

        if self.__verbose:
            print()
            self._printPorts()

    def _printPorts(self) -> None:
        """Read port infos from /etc/services and print open port infos."""

        @dataclass
        class PortInfo:
            protocol: str
            usage: str

            def __repr__(self):
                prot_info = colored(self.protocol, 'dark_grey')
                use_info = colored(self.usage, 'light_yellow')
                return f"\t{prot_info:} {use_info}"

        def parsePortInfo() -> dict:
            """Parse /etc/services and return a dictionary."""
            info_dict = {}
            with open("/etc/services", "r") as f:
                next(f)
                next(f)             # /etc/services top has two useless lines
                info_dict = {}
                r = re.compile("[ \t/]+")
                for line in f:
                    prog, port, prot = r.split(line[:-1])
                    info = PortInfo(protocol=prot, usage=prog)
                    if info_dict.get(int(port)) is None:
                        info_dict[int(port)] = [info]
                    else:
                        info_dict[int(port)].append(info)
            return info_dict

        info_dict = parsePortInfo()
        for port in self._open_ports:
            infos = info_dict[port]
            print(colored(f"{port}:", 'cyan'))
            print(*infos, sep="\n")
