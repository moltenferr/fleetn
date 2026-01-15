import socket
import threading
from time import time, sleep
from threading import Thread, Lock
from config import ADDRESS, PORT, MAX_CONNS, KEY_ROT_THRESHOLD, MAGIC_ROT
from utils import send_msg, recv_msg, debug, warn, error, success

from Crypto.PublicKey import ECC, RSA
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

SESSIONS = {}
SESSIONS_LOCK = Lock()

try:
    with open("server.key", "rb") as f:
        SERVER_RSA_KEY = RSA.import_key(f.read())
    with open("server.crt", "rb") as f:
        SERVER_CERT = f.read()
except Exception as e:
    print(f"Erro ao carregar chaves: {e}")
    exit(1)

def perform_handshake(conn):
    data = recv_msg(conn)
    if not data: return None, None
    
    cid = data[:16]
    pk_c = ECC.import_key(data[16:])
    
    # ECDHE Server
    ecc_srv = ECC.generate(curve='P-256')
    pk_s_bytes = ecc_srv.public_key().export_key(format='DER')
    salt = get_random_bytes(16)

    # Assinatura do handshake
    h = SHA256.new(pk_s_bytes + cid + data[16:] + salt)
    sig = pkcs1_15.new(SERVER_RSA_KEY).sign(h)

    # Resposta: pk_s | len_crt | crt | len_sig | sig | salt
    payload = (pk_s_bytes + 
               len(SERVER_CERT).to_bytes(2, 'big') + SERVER_CERT +
               len(sig).to_bytes(2, 'big') + sig + salt)
    send_msg(conn, payload)

    # Derivação de chaves
    z = int((ecc_srv.d * pk_c.pointQ).x).to_bytes(32, 'big')
    prk = HKDF(z, 32, salt, SHA256)
    
    return cid, {
        "conn": conn,
        "k_c2s": HKDF(prk, 16, b"c2s", SHA256),
        "k_s2c": HKDF(prk, 16, b"s2c", SHA256),
        "s_recv": 0,
        "s_send": 1,
        'msgs_until_rot': KEY_ROT_THRESHOLD
    }

def handle_conn(conn):
    cid = None
    try:
        cid, session = perform_handshake(conn)
        if not cid: return

        with SESSIONS_LOCK:
            SESSIONS[cid] = session
        
        success(f"Cliente {cid.hex()[:8]} autenticado.")

        while True:
            # Rotate keys
            with SESSIONS_LOCK:
                if session['msgs_until_rot'] <= 0:
                    pk_s = ECC.generate(curve='P-256')
                    salt = get_random_bytes(16)

                    send_msg(conn, MAGIC_ROT + pk_s.public_key().export_key(format='DER') + salt)
                    data = recv_msg(conn)
                    
                    if data and data[:2] == MAGIC_ROT:
                        pk_c = ECC.import_key(data[2:]).public_key()
                        z = int((pk_s.d * pk_c.pointQ).x).to_bytes(32, 'big')
                        prk = HKDF(z, 32, salt, SHA256)
                        session['k_c2s'] = HKDF(prk, 16, b'c2s', SHA256)
                        session['k_s2c'] = HKDF(prk, 16, b's2c', SHA256)
                        session['msgs_until_rot'] = KEY_ROT_THRESHOLD
                        debug(f'Keys for {cid.hex()[:8]} rotated')
            
            frame = recv_msg(conn)
            
            if not frame or len(frame) < 52: break

            nonce, snd, rcp, seq = frame[:12], frame[12:28], frame[28:44], frame[44:52]
            val_seq = int.from_bytes(seq, 'big')
            ciphertext_tag = frame[52:]

            # Validar remetente e replay
            if snd != cid or val_seq < session["s_recv"]:
                continue
            session["s_recv"] = val_seq + 1
            session['msgs_until_rot'] -= 1

            # Decriptação
            cipher = AES.new(session["k_c2s"], AES.MODE_GCM, nonce=nonce)
            cipher.update(snd + rcp + seq)
            
            try:
                msg = cipher.decrypt_and_verify(ciphertext_tag[:-16], ciphertext_tag[-16:])
                debug(f"De {snd.hex()[:6]} para {rcp.hex()[:6]}: {msg.decode()}")
            except:
                error("Falha de integridade detectada.")
                continue

            # Roteamento
            with SESSIONS_LOCK:
                target = SESSIONS.get(rcp)
                if target:
                    n_out = get_random_bytes(12)
                    s_out = target["s_send"].to_bytes(8, 'big')
                    
                    c_out = AES.new(target["k_s2c"], AES.MODE_GCM, nonce=n_out)
                    c_out.update(snd + rcp + s_out)
                    ct, tag = c_out.encrypt_and_digest(msg)
                    
                    send_msg(target["conn"], n_out + snd + rcp + s_out + ct + tag)
                    target["s_send"] += 1

    except Exception as e:
        error(f"Erro na conexao: {e}")
    finally:
        conn.close()
        if cid:
            with SESSIONS_LOCK: SESSIONS.pop(cid, None)
            warn(f"Cliente {cid.hex()[:8]} desconectado.")

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((ADDRESS, PORT))
        s.listen(MAX_CONNS)
        success(f"Servidor ativo em {ADDRESS}:{PORT}")
        while True:
            try:
                c, addr = s.accept()
                Thread(target=handle_conn, args=(c,), daemon=True).start()
            except socket.error:
                break 
                
    except KeyboardInterrupt:
        warn('\rEncerrando servidor...')
    finally:
        s.close()
