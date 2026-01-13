import socket
from colorama import Fore, Style

def is_conn_open(conn: socket.socket) -> bool:
    try:
        return len(conn.recv(1, socket.MSG_DONTWAIT | socket.MSG_PEEK)) == 1
    except BlockingIOError:
        return True

# Logging

def debug(message: str) -> None:
    print(Style.DIM + Fore.WHITE + message + Style.RESET_ALL)

def warn(message: str) -> None:
    print(Fore.YELLOW + message + Fore.RESET)

def error(message: str) -> None:
    print(Fore.RED + message + Fore.RESET)
