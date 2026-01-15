import socket
import threading
import sys
import os
from config import ADDRESS, PORT, MAGIC_ROT
from utils import send_msg, recv_msg, debug, warn, error, success

from Crypto.PublicKey import ECC, RSA
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

MY_ID = get_random_bytes(16)
SERVER_PK: RSA.RsaKey = None
K_C2S: ECC.EccKey = None
K_S2C: ECC.EccKey = None

def listen_server(conn):
    global SERVER_PK, K_C2S, K_S2C
    last_s = 0
    while True:
        try:
            data = recv_msg(conn)
            if not data: break

            # Rotate keys
            if data[:2] == MAGIC_ROT:
                pk_s, salt = ECC.import_key(data[2:-16]).public_key(), data[-16:]
                pk_c = ECC.generate(curve='P-256')
                send_msg(conn, MAGIC_ROT + pk_c.public_key().export_key(format='DER'))
                z = int((pk_c.d * pk_s.pointQ).x).to_bytes(32, 'big')
                prk = HKDF(z, 32, salt, SHA256)
                K_C2S, K_S2C = HKDF(prk, 16, b'c2s', SHA256), HKDF(prk, 16, b's2c', SHA256)
                continue
            
            # Parsing do pacote: nonce(12), de(16), para(16), seq(8), payload(restante)
            n, snd, rcp, seq = data[:12], data[12:28], data[28:44], data[44:52]
            v_seq = int.from_bytes(seq, 'big')
            
            if v_seq < last_s: continue
            last_s = v_seq + 1

            cipher = AES.new(K_S2C, AES.MODE_GCM, nonce=n)
            cipher.update(snd + rcp + seq)
            
            payload = data[52:]
            msg = cipher.decrypt_and_verify(payload[:-16], payload[-16:])
            
            print(f"\n[{snd.hex()[:8]}]: {msg.decode()}")
            print(f"Mensagem: ", end="", flush=True)
        except:
            break
    os._exit(0)

def start_handshake(c):
    global SERVER_PK
    # Gerar par ECDHE local
    ecc = ECC.generate(curve='P-256')
    pk_bytes = ecc.public_key().export_key(format='DER')
    send_msg(c, MY_ID + pk_bytes)

    # Receber Server Hello
    resp = recv_msg(c)
    pk_s_b = resp[:91]
    
    # Extrair Certificado e Assinatura
    idx = 91
    l_crt = int.from_bytes(resp[idx:idx+2], 'big'); idx += 2
    crt_b = resp[idx:idx+l_crt]; idx += l_crt
    l_sig = int.from_bytes(resp[idx:idx+2], 'big'); idx += 2
    sig_b = resp[idx:idx+l_sig]
    salt = resp[-16:]

    # Validar Identidade do Servidor
    SERVER_PK = srv_pub = RSA.import_key(crt_b)
    h = SHA256.new(pk_s_b + MY_ID + pk_bytes + salt)
    pkcs1_15.new(srv_pub).verify(h, sig_b)
    
    # Derivar chaves de sessao
    pk_s = ECC.import_key(pk_s_b)
    z = int((ecc.d * pk_s.pointQ).x).to_bytes(32, 'big')
    prk = HKDF(z, 32, salt, SHA256)
    
    return HKDF(prk, 16, b"c2s", SHA256), HKDF(prk, 16, b"s2c", SHA256)

if __name__ == '__main__':
    print(f"--- MEU ID: {MY_ID.hex()} ---")
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        c.connect((ADDRESS, PORT))
        K_C2S, K_S2C = start_handshake(c)
        success("Conexão segura estabelecida.")

        threading.Thread(target=listen_server, args=(c,), daemon=True).start()

        target_hex = input("Destinatário (ID Hex): ").strip()
        target_id = bytes.fromhex(target_hex)
        
        s_count = 1
        while True:
            txt = input("Mensagem: ")
            if not txt: continue
            
            n = get_random_bytes(12)
            seq_b = s_count.to_bytes(8, 'big')
            
            cipher = AES.new(K_C2S, AES.MODE_GCM, nonce=n)
            cipher.update(MY_ID + target_id + seq_b)
            
            ct, tag = cipher.encrypt_and_digest(txt.encode())
            send_msg(c, n + MY_ID + target_id + seq_b + ct + tag)
            s_count += 1

    except KeyboardInterrupt:
        print("\nSaindo...")
    except Exception as e:
        error(f"Falha: {e}")
    finally:
        c.close()
