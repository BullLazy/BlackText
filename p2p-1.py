import base64
import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL = b"BlackText-P2P-v1"
INVITE_PREFIX = "BT1-"

MAX_MESSAGE = 64 * 1024
MAX_FRAME = MAX_MESSAGE + 256


class ProtocolError(Exception):
    pass


def _b64e(data):
    return (
        base64.urlsafe_b64encode(data)
        .decode("ascii")
        .rstrip("=")
    )


def _b64d(text):
    padding = "=" * ((4 - len(text) % 4) % 4)

    try:
        return base64.urlsafe_b64decode(
            (text + padding).encode("ascii")
        )

    except Exception as exc:
        raise ProtocolError(
            "Davet kodu gecersiz"
        ) from exc


def _public_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _wipe(value):
    if isinstance(value, bytearray):
        for index in range(len(value)):
            value[index] = 0


def local_addresses():
    found = set()

    try:
        from jnius import autoclass

        NetworkInterface = autoclass(
            "java.net.NetworkInterface"
        )

        interfaces = (
            NetworkInterface.getNetworkInterfaces()
        )

        while (
            interfaces is not None
            and interfaces.hasMoreElements()
        ):
            interface = interfaces.nextElement()

            addresses = interface.getInetAddresses()

            while addresses.hasMoreElements():
                address = addresses.nextElement()

                if (
                    address.isLoopbackAddress()
                    or address.isLinkLocalAddress()
                ):
                    continue

                text = str(
                    address.getHostAddress()
                ).split("%", 1)[0]

                try:
                    found.add(
                        str(
                            ipaddress.ip_address(
                                text
                            )
                        )
                    )

                except ValueError:
                    pass

    except Exception:
        pass

    try:
        hostname = socket.gethostname()

        infos = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for info in infos:
            text = info[4][0].split(
                "%",
                1,
            )[0]

            try:
                address = ipaddress.ip_address(
                    text
                )

            except ValueError:
                continue

            if (
                address.is_loopback
                or address.is_link_local
            ):
                continue

            found.add(
                str(address)
            )

    except Exception:
        pass

    def rank(text):
        address = ipaddress.ip_address(
            text
        )

        if (
            address.version == 6
            and address.is_global
        ):
            return 0, text

        if (
            address.version == 4
            and address.is_private
        ):
            return 1, text

        if address.version == 6:
            return 2, text

        return 3, text

    return sorted(
        found,
        key=rank,
    )


def _make_invite(
    address,
    port,
    host_public,
    secret,
):
    ip = ipaddress.ip_address(
        address
    )

    family = (
        6
        if ip.version == 6
        else 4
    )

    payload = (
        b"\x01"
        + bytes([family])
        + ip.packed
        + struct.pack(
            ">H",
            port,
        )
        + host_public
        + bytes(secret)
    )

    return (
        INVITE_PREFIX
        + _b64e(payload)
    )


def _parse_invite(code):
    code = code.strip()

    if not code.startswith(
        INVITE_PREFIX
    ):
        raise ProtocolError(
            "Davet kodu gecersiz"
        )

    raw = _b64d(
        code[
            len(INVITE_PREFIX):
        ]
    )

    if (
        len(raw) < 2
        or raw[0] != 1
    ):
        raise ProtocolError(
            "Davet kodu gecersiz"
        )

    family = raw[1]

    if family == 6:
        address_size = 16

    elif family == 4:
        address_size = 4

    else:
        raise ProtocolError(
            "Davet kodu gecersiz"
        )

    expected = (
        2
        + address_size
        + 2
        + 32
        + 32
    )

    if len(raw) != expected:
        raise ProtocolError(
            "Davet kodu gecersiz"
        )

    offset = 2

    address = str(
        ipaddress.ip_address(
            raw[
                offset:
                offset + address_size
            ]
        )
    )

    offset += address_size

    port = struct.unpack(
        ">H",
        raw[
            offset:
            offset + 2
        ],
    )[0]

    offset += 2

    host_public = raw[
        offset:
        offset + 32
    ]

    offset += 32

    secret = bytearray(
        raw[
            offset:
            offset + 32
        ]
    )

    if port == 0:
        _wipe(secret)

        raise ProtocolError(
            "Davet kodu gecersiz"
        )

    return (
        address,
        port,
        host_public,
        secret,
    )


def _mac(
    secret,
    label,
    host_public,
    client_public,
):
    return hmac.new(
        bytes(secret),
        PROTOCOL
        + label
        + host_public
        + client_public,
        hashlib.sha256,
    ).digest()


def _derive_session(
    private_key,
    peer_public_bytes,
    secret,
    host_public,
    client_public,
    role,
):
    peer_public = (
        x25519.X25519PublicKey
        .from_public_bytes(
            peer_public_bytes
        )
    )

    shared = private_key.exchange(
        peer_public
    )

    transcript = (
        PROTOCOL
        + host_public
        + client_public
    )

    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=bytes(secret),
        info=transcript,
    ).derive(shared)

    client_to_host = material[:32]
    host_to_client = material[32:]

    if role == "host":
        send_key = host_to_client
        recv_key = client_to_host

    else:
        send_key = client_to_host
        recv_key = host_to_client

    security_digest = hmac.new(
        bytes(secret),
        b"security-code"
        + transcript
        + shared,
        hashlib.sha256,
    ).digest()

    number = (
        int.from_bytes(
            security_digest[:5],
            "big",
        )
        % 1_000_000_000
    )

    security_code = (
        f"{number:09d}"
    )

    security_code = (
        f"{security_code[:3]} "
        f"{security_code[3:6]} "
        f"{security_code[6:]}"
    )

    return (
        _Session(
            send_key,
            recv_key,
        ),
        security_code,
    )


class _Session:
    def __init__(
        self,
        send_key,
        recv_key,
    ):
        self._send = (
            ChaCha20Poly1305(
                send_key
            )
        )

        self._recv = (
            ChaCha20Poly1305(
                recv_key
            )
        )

        self._send_counter = 0
        self._recv_counter = 0

        self._send_lock = (
            threading.Lock()
        )

        self._recv_lock = (
            threading.Lock()
        )

    @staticmethod
    def _nonce(counter):
        return (
            b"\x00\x00\x00\x00"
            + counter.to_bytes(
                8,
                "big",
            )
        )

    @staticmethod
    def _aad(counter):
        return (
            PROTOCOL
            + b"-data-"
            + counter.to_bytes(
                8,
                "big",
            )
        )

    def encrypt(self, plaintext):
        with self._send_lock:
            counter = (
                self._send_counter
            )

            if counter >= (
                (1 << 64) - 1
            ):
                raise ProtocolError(
                    "Oturum siniri asildi"
                )

            ciphertext = (
                self._send.encrypt(
                    self._nonce(
                        counter
                    ),
                    plaintext,
                    self._aad(
                        counter
                    ),
                )
            )

            self._send_counter += 1

            return (
                counter.to_bytes(
                    8,
                    "big",
                )
                + ciphertext
            )

    def decrypt(self, packet):
        if len(packet) < 24:
            raise ProtocolError(
                "Paket gecersiz"
            )

        counter = int.from_bytes(
            packet[:8],
            "big",
        )

        with self._recv_lock:
            if counter != (
                self._recv_counter
            ):
                raise ProtocolError(
                    "Paket sirasi gecersiz"
                )

            try:
                plaintext = (
                    self._recv.decrypt(
                        self._nonce(
                            counter
                        ),
                        packet[8:],
                        self._aad(
                            counter
                        ),
                    )
                )

            except Exception as exc:
                raise ProtocolError(
                    "Paket dogrulanamadi"
                ) from exc

            self._recv_counter += 1

            return plaintext


class P2PNode:
    def __init__(
        self,
        on_status=None,
        on_message=None,
        on_invite=None,
        on_security=None,
    ):
        self.on_status = (
            on_status
            or (
                lambda value:
                None
            )
        )

        self.on_message = (
            on_message
            or (
                lambda value:
                None
            )
        )

        self.on_invite = (
            on_invite
            or (
                lambda value:
                None
            )
        )

        self.on_security = (
            on_security
            or (
                lambda value:
                None
            )
        )

        self._lock = (
            threading.RLock()
        )

        self._frame_send_lock = (
            threading.Lock()
        )

        self._stop_event = (
            threading.Event()
        )

        self._listener = None
        self._sock = None
        self._session = None
        self._host_secret = None

    @property
    def connected(self):
        with self._lock:
            return (
                self._sock
                is not None
                and self._session
                is not None
            )

    def start_host(
        self,
        advertised_address,
        port=0,
    ):
        self.disconnect()

        address = str(
            ipaddress.ip_address(
                advertised_address.strip()
            )
        )

        port = int(port)

        if (
            port < 0
            or port > 65535
        ):
            raise ValueError(
                "Port gecersiz"
            )

        stop_event = (
            threading.Event()
        )

        with self._lock:
            self._stop_event = (
                stop_event
            )

        threading.Thread(
            target=self._host_worker,
            args=(
                address,
                port,
                stop_event,
            ),
            daemon=True,
        ).start()

    def connect(
        self,
        invite_code,
    ):
        self.disconnect()

        if not invite_code.strip():
            raise ValueError(
                "Davet kodu bos"
            )

        stop_event = (
            threading.Event()
        )

        with self._lock:
            self._stop_event = (
                stop_event
            )

        threading.Thread(
            target=self._client_worker,
            args=(
                invite_code.strip(),
                stop_event,
            ),
            daemon=True,
        ).start()

    def send_text(
        self,
        text,
    ):
        if not isinstance(
            text,
            str,
        ):
            return False

        raw = text.encode(
            "utf-8"
        )

        if (
            not raw
            or len(raw)
            > MAX_MESSAGE
        ):
            return False

        with self._lock:
            sock = self._sock
            session = self._session

        if (
            sock is None
            or session is None
        ):
            return False

        try:
            packet = (
                session.encrypt(
                    b"\x01"
                    + raw
                )
            )

            with self._frame_send_lock:
                self._send_frame(
                    sock,
                    packet,
                )

            return True

        except Exception:
            self._fail(
                "Baglanti kesildi"
            )

            return False

    def disconnect(self):
        with self._lock:
            stop_event = (
                self._stop_event
            )

            listener = (
                self._listener
            )

            sock = self._sock

            secret = (
                self._host_secret
            )

            self._listener = None
            self._sock = None
            self._session = None
            self._host_secret = None

        stop_event.set()

        for item in (
            listener,
            sock,
        ):
            if item is None:
                continue

            try:
                item.shutdown(
                    socket.SHUT_RDWR
                )

            except Exception:
                pass

            try:
                item.close()

            except Exception:
                pass

        _wipe(secret)

    def _host_worker(
        self,
        address,
        port,
        stop_event,
    ):
        listener = None
        sock = None

        secret = bytearray(
            os.urandom(32)
        )

        try:
            private_key = (
                x25519
                .X25519PrivateKey
                .generate()
            )

            host_public = (
                _public_bytes(
                    private_key
                )
            )

            ip = ipaddress.ip_address(
                address
            )

            if ip.version == 6:
                family = (
                    socket.AF_INET6
                )

            else:
                family = (
                    socket.AF_INET
                )

            listener = socket.socket(
                family,
                socket.SOCK_STREAM,
            )

            listener.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1,
            )

            if family == socket.AF_INET6:
                try:
                    listener.setsockopt(
                        socket.IPPROTO_IPV6,
                        socket.IPV6_V6ONLY,
                        1,
                    )

                except Exception:
                    pass

            listener.settimeout(
                1.0
            )

            if family == socket.AF_INET6:
                bind_address = (
                    "::",
                    port,
                    0,
                    0,
                )

            else:
                bind_address = (
                    "0.0.0.0",
                    port,
                )

            listener.bind(
                bind_address
            )

            listener.listen(1)

            actual_port = (
                listener
                .getsockname()[1]
            )

            with self._lock:
                if (
                    self._stop_event
                    is not stop_event
                ):
                    return

                self._listener = (
                    listener
                )

                self._host_secret = (
                    secret
                )

            invite = _make_invite(
                address,
                actual_port,
                host_public,
                secret,
            )

            self.on_invite(
                invite
            )

            self.on_status(
                "Baglanti bekleniyor"
            )

            while not (
                stop_event.is_set()
            ):
                try:
                    sock, _ = (
                        listener.accept()
                    )

                    break

                except socket.timeout:
                    continue

            if (
                stop_event.is_set()
                or sock is None
            ):
                return

            with self._lock:
                if (
                    self._stop_event
                    is not stop_event
                ):
                    return

                self._sock = sock

            try:
                listener.close()

            except Exception:
                pass

            listener = None

            with self._lock:
                self._listener = None

            sock.settimeout(
                15.0
            )

            hello = (
                self._recv_frame(
                    sock
                )
            )

            if (
                len(hello)
                != 68
                or hello[:4]
                != b"BTC1"
            ):
                raise ProtocolError(
                    "El sikisma gecersiz"
                )

            client_public = (
                hello[4:36]
            )

            received_mac = (
                hello[36:68]
            )

            expected_mac = _mac(
                secret,
                b"client",
                host_public,
                client_public,
            )

            if not hmac.compare_digest(
                received_mac,
                expected_mac,
            ):
                raise ProtocolError(
                    "El sikisma gecersiz"
                )

            host_reply = (
                b"BTH1"
                + _mac(
                    secret,
                    b"host",
                    host_public,
                    client_public,
                )
            )

            self._send_frame(
                sock,
                host_reply,
            )

            session, security_code = (
                _derive_session(
                    private_key,
                    client_public,
                    secret,
                    host_public,
                    client_public,
                    "host",
                )
            )

            self._send_frame(
                sock,
                session.encrypt(
                    b"\x00READY"
                ),
            )

            answer = session.decrypt(
                self._recv_frame(
                    sock
                )
            )

            if answer != b"\x00READY":
                raise ProtocolError(
                    "Oturum dogrulanamadi"
                )

            sock.settimeout(
                None
            )

            with self._lock:
                if (
                    self._stop_event
                    is not stop_event
                    or stop_event.is_set()
                ):
                    return

                self._session = (
                    session
                )

                self._host_secret = (
                    None
                )

            _wipe(secret)
            secret = None

            self.on_invite("")

            self.on_security(
                security_code
            )

            self.on_status(
                "Baglandi"
            )

            self._receive_loop(
                sock,
                session,
                stop_event,
            )

        except Exception:
            if not (
                stop_event.is_set()
            ):
                self._fail(
                    "Baglanti kurulamadi"
                )

        finally:
            _wipe(secret)

            if listener is not None:
                try:
                    listener.close()

                except Exception:
                    pass

            if sock is not None:
                try:
                    sock.close()

                except Exception:
                    pass

    def _client_worker(
        self,
        invite_code,
        stop_event,
    ):
        sock = None
        secret = None

        try:
            (
                address,
                port,
                host_public,
                secret,
            ) = _parse_invite(
                invite_code
            )

            ip = ipaddress.ip_address(
                address
            )

            if ip.version == 6:
                family = (
                    socket.AF_INET6
                )

            else:
                family = (
                    socket.AF_INET
                )

            private_key = (
                x25519
                .X25519PrivateKey
                .generate()
            )

            client_public = (
                _public_bytes(
                    private_key
                )
            )

            sock = socket.socket(
                family,
                socket.SOCK_STREAM,
            )

            sock.settimeout(
                15.0
            )

            with self._lock:
                if (
                    self._stop_event
                    is not stop_event
                ):
                    return

                self._sock = sock

            self.on_status(
                "Baglaniyor"
            )

            if family == socket.AF_INET6:
                target = (
                    address,
                    port,
                    0,
                    0,
                )

            else:
                target = (
                    address,
                    port,
                )

            sock.connect(
                target
            )

            client_packet = (
                b"BTC1"
                + client_public
                + _mac(
                    secret,
                    b"client",
                    host_public,
                    client_public,
                )
            )

            self._send_frame(
                sock,
                client_packet,
            )

            reply = (
                self._recv_frame(
                    sock
                )
            )

            if (
                len(reply)
                != 36
                or reply[:4]
                != b"BTH1"
            ):
                raise ProtocolError(
                    "El sikisma gecersiz"
                )

            expected_mac = _mac(
                secret,
                b"host",
                host_public,
                client_public,
            )

            if not hmac.compare_digest(
                reply[4:],
                expected_mac,
            ):
                raise ProtocolError(
                    "El sikisma gecersiz"
                )

            session, security_code = (
                _derive_session(
                    private_key,
                    host_public,
                    secret,
                    host_public,
                    client_public,
                    "client",
                )
            )

            ready = session.decrypt(
                self._recv_frame(
                    sock
                )
            )

            if ready != b"\x00READY":
                raise ProtocolError(
                    "Oturum dogrulanamadi"
                )

            self._send_frame(
                sock,
                session.encrypt(
                    b"\x00READY"
                ),
            )

            _wipe(secret)
            secret = None

            sock.settimeout(
                None
            )

            with self._lock:
                if (
                    self._stop_event
                    is not stop_event
                    or stop_event.is_set()
                ):
                    return

                self._session = (
                    session
                )

            self.on_security(
                security_code
            )

            self.on_status(
                "Baglandi"
            )

            self._receive_loop(
                sock,
                session,
                stop_event,
            )

        except Exception:
            if not (
                stop_event.is_set()
            ):
                self._fail(
                    "Baglanti kurulamadi"
                )

        finally:
            _wipe(secret)

            if sock is not None:
                try:
                    sock.close()

                except Exception:
                    pass

    def _receive_loop(
        self,
        sock,
        session,
        stop_event,
    ):
        try:
            while not (
                stop_event.is_set()
            ):
                packet = (
                    self._recv_frame(
                        sock
                    )
                )

                plaintext = (
                    session.decrypt(
                        packet
                    )
                )

                if (
                    not plaintext
                    or plaintext[0]
                    != 1
                ):
                    raise ProtocolError(
                        "Paket tipi gecersiz"
                    )

                raw = plaintext[1:]

                if (
                    len(raw)
                    > MAX_MESSAGE
                ):
                    raise ProtocolError(
                        "Mesaj cok buyuk"
                    )

                try:
                    text = raw.decode(
                        "utf-8"
                    )

                except UnicodeDecodeError as exc:
                    raise ProtocolError(
                        "Mesaj kodlamasi gecersiz"
                    ) from exc

                self.on_message(
                    text
                )

        except Exception:
            if not (
                stop_event.is_set()
            ):
                self._fail(
                    "Baglanti kesildi"
                )

    def _fail(
        self,
        status,
    ):
        self.disconnect()

        self.on_status(
            status
        )

    @staticmethod
    def _send_frame(
        sock,
        data,
    ):
        if (
            not data
            or len(data)
            > MAX_FRAME
        ):
            raise ProtocolError(
                "Paket boyutu gecersiz"
            )

        sock.sendall(
            struct.pack(
                ">I",
                len(data),
            )
            + data
        )

    @staticmethod
    def _recv_exact(
        sock,
        size,
    ):
        chunks = []

        remaining = size

        while remaining:
            chunk = sock.recv(
                remaining
            )

            if not chunk:
                raise ConnectionError(
                    "Baglanti kapandi"
                )

            chunks.append(
                chunk
            )

            remaining -= len(
                chunk
            )

        return b"".join(
            chunks
        )

    @classmethod
    def _recv_frame(
        cls,
        sock,
    ):
        header = cls._recv_exact(
            sock,
            4,
        )

        size = struct.unpack(
            ">I",
            header,
        )[0]

        if (
            size <= 0
            or size > MAX_FRAME
        ):
            raise ProtocolError(
                "Paket boyutu gecersiz"
            )

        return cls._recv_exact(
            sock,
            size,
        )
