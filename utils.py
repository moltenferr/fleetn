import socket
import struct
from colorama import Fore, Style

def send_msg(conn, data):
    length = len(data)
    conn.sendall(struct.pack("!I", length) + data)

def recv_msg(conn):
    raw_len = _recv_exact(conn, 4)
    if not raw_len:
        return None
    length = struct.unpack("!I", raw_len)[0]
    return _recv_exact(conn, length)

def _recv_exact(conn, n):
    data = b""
    while len(data) < n:
        packet = conn.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def debug(msg):
    print(f"{Style.DIM}{Fore.WHITE}[DEBUG] {msg}{Style.RESET_ALL}")

def warn(msg):
    print(f"{Fore.YELLOW}[AVISO] {msg}{Style.RESET_ALL}")

def error(msg):
    print(f"{Fore.RED}[ERRO] {msg}{Style.RESET_ALL}")

def success(msg):
    print(f"{Fore.GREEN}[OK] {msg}{Style.RESET_ALL}")