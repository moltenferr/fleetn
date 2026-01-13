from config import ADDRESS, PORT, MAX_CONNS
from utils import is_conn_open, debug, warn

import socket
from threading import Thread
from colorama import Fore, Style


CONNS = {}

def handle_conn(conn: socket.socket) -> None:
    key = str(conn.getpeername())

    while is_conn_open(conn):
        data = conn.recv(8_192)
        if len(data) == 0:
            continue

    conn.close()
    del CONNS[key]
    debug(f'Connection with {key} dropped; {len(CONNS)} active.')

if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    
    server.bind((ADDRESS, PORT))
    server.listen(MAX_CONNS)

    try:
        while True:
            conn, raddr = server.accept()
            print(f'Connection from {raddr}')
            CONNS[str(conn.getpeername())] = conn
            Thread(target=handle_conn, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        warn('\rReceived Ctrl+C')
    finally:
        server.close()
