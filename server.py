import socket
from threading import Thread, Lock

from config import ADDRESS, PORT, MAX_CONNS, KEY_ROT_THRESHOLD, MAGIC_ROT
from utils import send_msg, recv_msg, success, debug, warn, error, die, ex_info

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
    die(f"Erro ao carregar chave/certificado: {e}")


class Security:
    @staticmethod
    def rotate_session_keys(conn, cid, session):
        try:
            debug(f"Iniciando rotação de chaves para {cid.hex()[:8]}")

            ecc_srv = ECC.generate(curve="P-256")
            pk_s_bytes = ecc_srv.public_key().export_key(format="DER")
            salt = get_random_bytes(16)
            sig = pkcs1_15.new(SERVER_RSA_KEY).sign(SHA256.new(pk_s_bytes + salt))

            send_msg(conn, MAGIC_ROT + pk_s_bytes + salt + sig)

            data = recv_msg(conn)
            if not data or not data.startswith(MAGIC_ROT):
                return False

            pk_c = ECC.import_key(data[len(MAGIC_ROT):]).public_key()
            z = int((ecc_srv.d * pk_c.pointQ).x).to_bytes(32, "big")
            prk = HKDF(z, 32, salt, SHA256)

            with SESSIONS_LOCK:
                session["k_c2s"] = HKDF(prk, 16, b"c2s", SHA256)
                session["k_s2c"] = HKDF(prk, 16, b"s2c", SHA256)
                session["msgs_until_rot"] = KEY_ROT_THRESHOLD

            success(f"Chaves rotacionadas para {cid.hex()[:8]}")
            return True

        except Exception as e:
            error(f"Erro ao rotacionar chaves de {cid.hex()[:8]}: {e}")
            return False


def perform_handshake(conn):
    try:
        data = recv_msg(conn)
        if not data:
            return None, None

        cid = data[:16]
        pk_c = ECC.import_key(data[16:])

        ecc_srv = ECC.generate(curve="P-256")
        pk_s_bytes = ecc_srv.public_key().export_key(format="DER")
        salt = get_random_bytes(16)

        h = SHA256.new(pk_s_bytes + cid + data[16:] + salt)
        sig = pkcs1_15.new(SERVER_RSA_KEY).sign(h)

        payload = (
            pk_s_bytes +
            len(SERVER_CERT).to_bytes(2, "big") + SERVER_CERT +
            len(sig).to_bytes(2, "big") + sig +
            salt
        )
        send_msg(conn, payload)

        z = int((ecc_srv.d * pk_c.pointQ).x).to_bytes(32, "big")
        prk = HKDF(z, 32, salt, SHA256)

        session = {
            "conn": conn,
            "k_c2s": HKDF(prk, 16, b"c2s", SHA256),
            "k_s2c": HKDF(prk, 16, b"s2c", SHA256),
            "s_recv": 0,
            "s_send": 1,
            "msgs_until_rot": KEY_ROT_THRESHOLD
        }

        return cid, session

    except Exception as e:
        error(f"Erro no handshake: {e}")
        return None, None


def handle_conn(conn):
    cid = None

    try:
        cid, session = perform_handshake(conn)
        if not cid:
            conn.close()
            return

        with SESSIONS_LOCK:
            SESSIONS[cid] = session

        success(f"Cliente {cid.hex()[:8]} conectado")

        while True:
            if session["msgs_until_rot"] <= 0:
                if not Security.rotate_session_keys(conn, cid, session):
                    break

            frame = recv_msg(conn)
            if not frame or len(frame) < 68:
                break

            nonce = frame[:12]
            snd = frame[12:28]
            rcp = frame[28:44]
            seq = frame[44:52]

            if snd != cid:
                warn("CID inválido no frame recebido")
                continue

            val_seq = int.from_bytes(seq, "big")
            if val_seq < session["s_recv"]:
                warn("Tentativa de replay detectada")
                continue

            cipher = AES.new(session["k_c2s"], AES.MODE_GCM, nonce=nonce)
            cipher.update(snd + rcp + seq)

            try:
                ciphertext = frame[52:-16]
                tag = frame[-16:]
                msg = cipher.decrypt_and_verify(ciphertext, tag)
                debug(f"De {snd.hex()[:8]} para {rcp.hex()[:8]}: {msg.decode(errors='ignore')}")
            except Exception:
                warn("Falha de integridade GCM")
                continue

            with SESSIONS_LOCK:
                session["s_recv"] = val_seq + 1
                session["msgs_until_rot"] -= 1
                target = SESSIONS.get(rcp)

            if not target:
                warn(f"Destino {rcp.hex()[:8]} não encontrado")
                continue

            nonce_out = get_random_bytes(12)
            seq_out = target["s_send"].to_bytes(8, "big")

            cipher_out = AES.new(target["k_s2c"], AES.MODE_GCM, nonce=nonce_out)
            cipher_out.update(snd + rcp + seq_out)
            ct, tag = cipher_out.encrypt_and_digest(msg)

            send_msg(
                target["conn"],
                nonce_out + snd + rcp + seq_out + ct + tag
            )

            with SESSIONS_LOCK:
                target["s_send"] += 1

    except Exception as e:
        error(f"[{ex_info()}] Erro na conexão {cid.hex() if cid else '???'}: {e}")

    finally:
        if cid:
            with SESSIONS_LOCK:
                SESSIONS.pop(cid, None)
            warn(f"Cliente {cid.hex()[:8]} desconectado")

        conn.close()


if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((ADDRESS, PORT))
        server.listen(MAX_CONNS)
        success(f"Servidor ativo em {ADDRESS}:{PORT}")

        while True:
            conn, _ = server.accept()
            Thread(target=handle_conn, args=(conn,), daemon=True).start()

    except KeyboardInterrupt:
        warn("\nEncerrando servidor")

    except Exception as e:
        error(f"Erro fatal: {e}")

    finally:
        server.close()
