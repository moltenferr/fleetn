from config import ADDRESS, PORT

import socket
from colorama import Fore

if __name__ == '__main__':
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        conn.connect((ADDRESS, PORT))
        while True:
            pass
    except Exception as err:
        print(Fore.RED + f'{err}')
    finally:
        conn.close()
