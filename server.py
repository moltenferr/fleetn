import socket
from threading import Thread, Lock

from config import ADDRESS, PORT, MAX_CONNS, KEY_ROT_THRESHOLD, MAGIC_ROT
from utils import send_msg, recv_msg
from utils import success, debug, warn, error, die, ex_info

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
    die(f'[{ex_info()}] Erro ao carregar chave/certificado: {e}')

def perform_handshake(conn):
    data = recv_msg(conn)
    if not data:
        return None, None
    
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

def handle_conn(conn: socket.socket):
    cid = None
    try:
        cid, session = perform_handshake(conn)
        if not cid:
            addr, port = conn.getpeername()
            warn(f'Handshake inválido de {addr}:{port}')
            conn.close()
            return

        with SESSIONS_LOCK:
            SESSIONS[cid] = session
        
        success(f'Cliente {cid.hex()[:8]} autenticado.')

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
                        debug(f'Chaves com {cid.hex()[:8]} rotacionadas.')
                    else:
                        warn(f'Falha rotacionando chaves de {cid.hex()[:8]}; encerrando conexão.')
                        conn.close()
                        return
            
            frame = recv_msg(conn)
            
            if not frame or len(frame) < 52:
                break

            nonce, sender, recipient, seq_no = frame[:12], frame[12:28], frame[28:44], frame[44:52]
            val_seq_no = int.from_bytes(seq_no, 'big')
            ciphertext_tag = frame[52:]

            # Check for valid recipient and anti-replay
            if sender != cid or val_seq_no < session['s_recv']:
                continue

            with SESSIONS_LOCK:
                session['s_recv'] = val_seq_no + 1
                session['msgs_until_rot'] -= 1

            # Decryption
            with SESSIONS_LOCK:
                cipher = AES.new(session['k_c2s'], AES.MODE_GCM, nonce=nonce)
            cipher.update(sender + recipient + seq_no)
            
            try:
                msg = cipher.decrypt_and_verify(ciphertext_tag[:-16], ciphertext_tag[-16:])
                debug(f'De {sender.hex()[:6]} para {recipient.hex()[:6]}: {msg.decode()}')
            except Exception as _:
                warn(f'Falha de autenticidade/integridade detectada. ({sender.hex()[:6]} -> {recipient.hex()[:6]})')
                continue 

            # Forwarding
            with SESSIONS_LOCK:
                target = SESSIONS.get(recipient)
                if target:
                    nonce_out = get_random_bytes(12)
                    seq_out = target['s_send'].to_bytes(8, 'big')
                    
                    cipher_out = AES.new(target['k_s2c'], AES.MODE_GCM, nonce=nonce_out)
                    cipher_out.update(sender + recipient + seq_out)
                    ct, tag = cipher_out.encrypt_and_digest(msg)
                    
                    send_msg(target['conn'], nonce_out + sender + recipient + seq_out + ct + tag)
                    target['s_send'] += 1
                else:
                    warn(f'CID não encontrado: {recipient.hex()[:6]}')

    except Exception as e:
        error(f'[{ex_info()}] Erro na conexão: {e}')
    finally:
        conn.close()
        if cid:
            with SESSIONS_LOCK:
                SESSIONS.pop(cid, None)
            warn(f'Cliente {cid.hex()[:6]} desconectado.')

if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((ADDRESS, PORT))
        server.listen(MAX_CONNS)
        success(f'Servidor ativo em {ADDRESS}:{PORT}')
        
        while True:
            conn, _addr = server.accept()
            Thread(target=handle_conn, args=(conn,), daemon=True).start()
                
    except KeyboardInterrupt:
        warn('\rEncerrando servidor ...')
    except Exception as e:
        error(f'[{ex_info()}] {e}')
    finally:
        server.close()
