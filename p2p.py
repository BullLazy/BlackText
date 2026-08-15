import ipaddress
import socket
import struct
import threading

from crypto_session import (
    MAX_FRAME,
    MAX_MESSAGE,
    ProtocolError,
    client_hello,
    derive_session,
    host_hello,
    make_invite,
    new_host_material,
    parse_invite,
    public_bytes,
    verify_client_hello,
    verify_host_hello,
)
from cryptography.hazmat.primitives.asymmetric import x25519


class P2PNode:
    def __init__(self, on_status=None, on_message=None, on_invite=None, on_security=None):
        self.on_status = on_status or (lambda value: None)
        self.on_message = on_message or (lambda value: None)
        self.on_invite = on_invite or (lambda value: None)
        self.on_security = on_security or (lambda value: None)
        self._lock = threading.RLock()
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._listener = None
        self._sock = None
        self._session = None
        self._host_private = None
        self._host_secret = None
        self._role = None

    @property
    def connected(self):
        with self._lock:
            return self._sock is not None and self._session is not None

    def start_host(self, advertised_address, port=0):
        self.disconnect()
        address = str(ipaddress.ip_address(advertised_address.strip()))
        thread = threading.Thread(target=self._host_worker, args=(address, int(port)), daemon=True)
        thread.start()

    def connect(self, invite_code):
        self.disconnect()
        thread = threading.Thread(target=self._client_worker, args=(invite_code.strip(),), daemon=True)
        thread.start()

    def send_text(self, text):
        if not isinstance(text, str):
            return False
        raw = text.encode("utf-8")
        if not raw or len(raw) > MAX_MESSAGE:
            return False
        with self._lock:
            sock = self._sock
            session = self._session
        if sock is None or session is None:
            return False
        try:
            packet = session.encrypt(b"\x01" + raw)
            with self._send_lock:
                self._send_frame(sock, packet)
            return True
        except Exception:
            self._fail("Baglanti kesildi")
            return False

    def disconnect(self):
        self._stop.set()
        with self._lock:
            listener = self._listener
            sock = self._sock
            self._listener = None
            self._sock = None
            self._session = None
            self._host_private = None
            secret = self._host_secret
            self._host_secret = None
            self._role = None
        for item in (listener, sock):
            if item is not None:
                try:
                    item.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    item.close()
                except Exception:
                    pass
        if isinstance(secret, bytearray):
            for i in range(len(secret)):
                secret[i] = 0
        self._stop = threading.Event()

    def _host_worker(self, address, port):
        try:
            family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
            private_key, secret = new_host_material()
            host_public_key = public_bytes(private_key)
            listener = socket.socket(family, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.settimeout(1.0)
            bind_address = ("::", port) if family == socket.AF_INET6 else ("0.0.0.0", port)
            listener.bind(bind_address)
            listener.listen(1)
            actual_port = listener.getsockname()[1]
            with self._lock:
                self._listener = listener
                self._host_private = private_key
                self._host_secret = secret
                self._role = "host"
            invite = make_invite(address, actual_port, host_public_key, secret)
            self.on_invite(invite)
            self.on_status("Baglanti bekleniyor")
            while not self._stop.is_set():
                try:
                    sock, _ = listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            try:
                listener.close()
            except Exception:
                pass
            with self._lock:
                self._listener = None
            sock.settimeout(15.0)
            hello = self._recv_frame(sock)
            client_public_key = verify_client_hello(hello, bytes(secret), host_public_key)
            self._send_frame(sock, host_hello(bytes(secret), host_public_key, client_public_key))
            session, security_code = derive_session(
                private_key,
                client_public_key,
                bytes(secret),
                host_public_key,
                client_public_key,
                "host",
            )
            self._send_frame(sock, session.encrypt(b"\x00READY"))
            answer = session.decrypt(self._recv_frame(sock))
            if answer != b"\x00READY":
                raise ProtocolError("Oturum dogrulanamadi")
            sock.settimeout(None)
            with self._lock:
                self._sock = sock
                self._session = session
                self._host_private = None
                self._role = "host"
            self.on_security(security_code)
            self.on_status("Baglandi")
            self._receive_loop(sock, session)
        except Exception:
            if not self._stop.is_set():
                self._fail("Baglanti kurulamadi")

    def _client_worker(self, invite_code):
        sock = None
        try:
            address, port, host_public_key, secret = parse_invite(invite_code)
            family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
            private_key = x25519.X25519PrivateKey.generate()
            client_public_key = public_bytes(private_key)
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(15.0)
            self.on_status("Baglaniyor")
            sock.connect((address, port))
            self._send_frame(sock, client_hello(secret, host_public_key, client_public_key))
            hello = self._recv_frame(sock)
            verify_host_hello(hello, secret, host_public_key, client_public_key)
            session, security_code = derive_session(
                private_key,
                host_public_key,
                secret,
                host_public_key,
                client_public_key,
                "client",
            )
            ready = session.decrypt(self._recv_frame(sock))
            if ready != b"\x00READY":
                raise ProtocolError("Oturum dogrulanamadi")
            self._send_frame(sock, session.encrypt(b"\x00READY"))
            sock.settimeout(None)
            with self._lock:
                self._sock = sock
                self._session = session
                self._role = "client"
            self.on_security(security_code)
            self.on_status("Baglandi")
            self._receive_loop(sock, session)
        except Exception:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            if not self._stop.is_set():
                self._fail("Baglanti kurulamadi")

    def _receive_loop(self, sock, session):
        try:
            while not self._stop.is_set():
                packet = self._recv_frame(sock)
                plaintext = session.decrypt(packet)
                if not plaintext:
                    raise ProtocolError("Bos paket")
                if plaintext[0] != 1:
                    raise ProtocolError("Paket tipi gecersiz")
                raw = plaintext[1:]
                if len(raw) > MAX_MESSAGE:
                    raise ProtocolError("Mesaj cok buyuk")
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ProtocolError("Mesaj kodlamasi gecersiz") from exc
                self.on_message(text)
        except Exception:
            if not self._stop.is_set():
                self._fail("Baglanti kesildi")

    def _fail(self, status):
        self.disconnect()
        self.on_status(status)

    @staticmethod
    def _send_frame(sock, data):
        if len(data) > MAX_FRAME:
            raise ProtocolError("Paket cok buyuk")
        sock.sendall(struct.pack(">I", len(data)) + data)

    @staticmethod
    def _recv_exact(sock, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError("Baglanti kapandi")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @classmethod
    def _recv_frame(cls, sock):
        size = struct.unpack(">I", cls._recv_exact(sock, 4))[0]
        if size <= 0 or size > MAX_FRAME:
            raise ProtocolError("Paket boyutu gecersiz")
        return cls._recv_exact(sock, size)
