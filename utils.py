import socket
import struct
from colorama import Fore, Style
from sys import exit, exc_info
from os.path import split

# Socket utils

def send_msg(conn: socket.socket, data: bytes) -> None:
    length = len(data)
    conn.sendall(struct.pack("!I", length) + data)

def recv_msg(conn: socket.socket) -> bytes | None:
    raw_len = _recv_exact(conn, 4)
    if not raw_len:
        return None
    length = struct.unpack("!I", raw_len)[0]
    return _recv_exact(conn, length)

def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    data = b''
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# Logging utils

def success(message: str) -> None:
    print(f'{Fore.GREEN}[OK] {message}{Style.RESET_ALL}')

def debug(message: str) -> None:
    print(f"{Style.DIM}{Fore.WHITE}[DEBUG] {message}{Style.RESET_ALL}")

def warn(message: str) -> None:
    print(f"{Fore.YELLOW}[AVISO] {message}{Style.RESET_ALL}")

def error(message: str) -> None:
    print(f"{Fore.RED}[ERRO] {message}{Style.RESET_ALL}")

def die(message: str) -> None:
    print(f'{Fore.RED}[CRÍTICO] {message}{Style.RESET_ALL}')
    exit(1)

def ex_info() -> str:
    _, _, tb = exc_info()
    return f'{split(tb.tb_frame.f_code.co_filename)[1]}:{tb.tb_lineno}'
