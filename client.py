from config import ADDRESS, PORT, MAX_MSG_LEN
from utils import is_conn_open, debug, warn, error

import socket


def handle_conn(conn: socket.socket) -> None:
    while is_conn_open(conn):
        _data = conn.recv(MAX_MSG_LEN)
    debug('Connection closed.')

if __name__ == '__main__':
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        conn.connect((ADDRESS, PORT))
        handle_conn(conn)
    except KeyboardInterrupt:
        warn('\rReceived Ctrl+C')
    except Exception as err:
        error(f'{err}')
    finally:
        conn.close()
