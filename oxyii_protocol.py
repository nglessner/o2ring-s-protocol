"""OxyII application-layer protocol for the Wellue T8520 / O2Ring-S.

Pure functions; no I/O. Frame codec, AES wrap/unwrap, opcode constants,
reply parsers. Verified against HCI snoop captures of the vendor app
and against live ring traffic.

Frame format (request and response share opcode):

    +------+-----+------+------+-----+--------+--------+----------+-----+
    | 0xA5 | cmd | ~cmd | flag | seq | len_lo | len_hi | payload  | crc |
    +------+-----+------+------+-----+--------+--------+----------+-----+
       1     1     1      1     1     1        1        len bytes   1

  - flag is 0x00 in app->device commands, 0x01 in device->app replies.
  - len is little-endian payload byte count.
  - seq is a 1-byte counter the device echoes in its replies; reuse
    across requests is accepted (i.e. it does not appear to be enforced
    as a strict monotonic).
  - crc is CRC-8 with polynomial 0x07 (init 0, no reflection, no xorout)
    over the entire frame *including* the 0xA5 lead and *excluding* only
    the crc byte itself.

Encryption is per-command: each request can be sent with or without an
AES key. With key, the *payload only* is AES/ECB/PKCS7-encrypted; the
envelope (header + crc) is then computed over the resulting ciphertext.
In observed traffic almost every command is plaintext. The exception is
cmd=0xFF (auth), which uses a XOR scheme rather than AES — see
`derive_session_key` and the README for details. The 16-byte AES
session key is NOT delivered in any reply; it is derived locally on
both ends from a shared algorithm.
"""

# Application-layer opcodes observed on the wire.
OP_SET_UTC_TIME = 0xC0
OP_GET_INFO = 0xE1
OP_GET_BATTERY = 0xE4
OP_GET_FILE_LIST = 0xF1
OP_READ_FILE_START = 0xF2
OP_READ_FILE_DATA = 0xF3
OP_READ_FILE_END = 0xF4

FRAME_LEAD = 0xA5
FRAME_HEADER_LEN = 7  # 0xA5, cmd, ~cmd, flag, seq, len_lo, len_hi


def crc8(data: bytes) -> int:
    """CRC-8 with polynomial 0x07, init 0, no reflection, no xorout.

    Verified against captured vendor-app frames. Caller is responsible
    for passing the right scope: full frame bytes minus the trailing
    crc byte itself.
    """
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def encode_frame(opcode: int, payload: bytes, seq: int = 0, flag: int = 0x00) -> bytes:
    """Build a complete request frame ready to write to the OxyII write characteristic."""
    if not 0 <= opcode <= 0xFF:
        raise ValueError(f"opcode out of byte range: {opcode}")
    length = len(payload)
    if length > 0xFFFF:
        raise ValueError(f"payload too long: {length}")
    header = bytes([
        FRAME_LEAD,
        opcode,
        (~opcode) & 0xFF,
        flag,
        seq & 0xFF,
        length & 0xFF,
        (length >> 8) & 0xFF,
    ])
    body = header + payload
    return body + bytes([crc8(body)])


class FrameDecodeError(ValueError):
    """Raised when an incoming OxyII frame fails validation."""


def decode_frame(frame: bytes) -> tuple[int, bytes, int]:
    """Validate and split a notify frame.

    Returns (opcode, payload, seq). Raises FrameDecodeError on any
    validation failure (lead byte, complement byte, crc, length).
    """
    if len(frame) < FRAME_HEADER_LEN + 1:
        raise FrameDecodeError(f"frame too short: {len(frame)} bytes")
    if frame[0] != FRAME_LEAD:
        raise FrameDecodeError(f"bad lead byte: 0x{frame[0]:02x}")
    opcode = frame[1]
    if frame[2] != (~opcode) & 0xFF:
        raise FrameDecodeError(
            f"opcode complement mismatch: cmd=0x{opcode:02x} "
            f"~cmd=0x{frame[2]:02x}"
        )
    seq = frame[4]
    length = frame[5] | (frame[6] << 8)
    expected_total = FRAME_HEADER_LEN + length + 1
    if len(frame) != expected_total:
        raise FrameDecodeError(
            f"frame length mismatch: declared payload={length}, "
            f"got total={len(frame)} (expected {expected_total})"
        )
    body = frame[:-1]
    expected_crc = crc8(body)
    if frame[-1] != expected_crc:
        raise FrameDecodeError(
            f"crc mismatch: expected 0x{expected_crc:02x}, got 0x{frame[-1]:02x}"
        )
    payload = bytes(frame[FRAME_HEADER_LEN:FRAME_HEADER_LEN + length])
    return opcode, payload, seq


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_BLOCK_SIZE = 16


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128/ECB/PKCS7 encrypt — matches the vendor-app encryption mode."""
    if len(key) != AES_BLOCK_SIZE:
        raise ValueError(f"key must be 16 bytes, got {len(key)}")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES_BLOCK_SIZE))


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-128/ECB/PKCS7 decrypt — matches the vendor-app encryption mode."""
    if len(key) != AES_BLOCK_SIZE:
        raise ValueError(f"key must be 16 bytes, got {len(key)}")
    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError(f"ciphertext not block-aligned: {len(ciphertext)}")
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)


import hashlib
from dataclasses import dataclass


# Protocol constant: MD5 of the literal ASCII string "lepucloud", used
# as a salt for session-key derivation. The AES-128 session key is not
# delivered in any reply; it is derived locally on both ends from this
# constant + a serial-prefix + a timestamp (see derive_session_key).
LEPUCLOUD_MD5 = hashlib.md5(b"lepucloud").digest()  # 16 bytes


@dataclass
class DeviceInfo:
    """Parsed GET_INFO reply payload.

    Layout observed on the wire from a captured vendor-app exchange.
    The 60-byte payload:

      [0..1]    u16  size-of-block / record count
      [2..3]    u16  protocol version
      [4..7]    4B   flags / type
      [8]       u8   separator (always 0x00)
      [9..16]   8B   firmware version, ASCII (e.g. "2D010002")
      [17]      u8   separator (always 0x01)
      [18..19]  u16  battery / capacity (LE)
      [20..21]  u16  storage / total samples (LE)
      [22..23]  u16  flags
      [24..31]  8B   datetime: year-LE, month, day, hour, minute, second, tz
      [32..35]  4B   build / model code
      [36..37]  u16  reserved
      [37]      u8   serial-number length (typically 10)
      [38..37+sn_len]  sn ASCII (e.g. "25B2303210")
      remainder:  zero padding

    Only `sn` and `firmware_version` are surfaced as parsed fields; the
    rest stays in `raw` for reference / future expansion.
    """
    raw: bytes
    sn: str = ""
    firmware_version: str = ""


def parse_get_info(payload: bytes) -> DeviceInfo:
    """Parse a GET_INFO reply payload (60-byte plaintext)."""
    if len(payload) < 48:
        raise FrameDecodeError(f"GET_INFO reply too short: {len(payload)}")
    fw_version = payload[9:17].decode("ascii", errors="replace").rstrip("\x00")
    sn_len = payload[37]
    if sn_len <= 0 or 38 + sn_len > len(payload):
        sn = ""
    else:
        sn = payload[38:38 + sn_len].decode("ascii", errors="replace")
    return DeviceInfo(raw=payload, sn=sn, firmware_version=fw_version)


def derive_session_key(serial: str, timestamp_seconds: int) -> bytes:
    """Compute the 16-byte AES session key shared by host and device.

    Layout:
      bytes [0..7]   = MD5("lepucloud") at even indices [0,2,4,6,8,10,12,14]
      bytes [8..11]  = first 4 ASCII chars of `serial`
      bytes [12..15] = (ts >> 0), (ts >> 1), (ts >> 2), (ts >> 3) & 0xFF

    The peculiar bit-shift pattern in the last 4 bytes (rather than the
    usual byte-extract `>> 0, 8, 16, 24`) is what the device expects;
    both sides compute it the same way. `serial` may be the device's
    full serial-number prefix or the literal "0000" (recommended as a
    portable default — see README).
    """
    if len(serial) < 4:
        raise ValueError(f"serial too short for key derivation: {serial!r}")
    key = bytearray(16)
    for i in range(8):
        key[i] = LEPUCLOUD_MD5[i * 2]
    key[8:12] = serial[:4].encode("ascii")
    for n in range(4):
        key[12 + n] = (timestamp_seconds >> n) & 0xFF
    return bytes(key)


@dataclass
class FileEntry:
    name: str
    size: int


@dataclass
class FileList:
    raw: bytes
    files: list[FileEntry]


def parse_file_list(plaintext: bytes) -> FileList:
    """Parse a GET_FILE_LIST reply (validated against live ring).

    Layout from a real T8520 reply (33 bytes for 2 files):
      [0]      u8   count
      [1..]    N x  16-byte name slot: 14-byte ASCII name (e.g.
                    "20260427105949") + 2 zero pad bytes.

    Names are timestamps in `YYYYMMDDhhmmss` format. File size is NOT
    in this reply; it must be inferred from streaming reads or read
    until READ_FILE_END.
    """
    if not plaintext:
        return FileList(raw=plaintext, files=[])
    count = plaintext[0]
    files: list[FileEntry] = []
    pos = 1
    SLOT = 16
    for _ in range(count):
        if pos + SLOT > len(plaintext):
            break
        slot = plaintext[pos:pos + SLOT]
        # Trim trailing zero pad and decode the name portion as ASCII.
        name = slot.rstrip(b"\x00").decode("ascii", errors="replace")
        files.append(FileEntry(name=name, size=0))
        pos += SLOT
    return FileList(raw=plaintext, files=files)


def build_read_file_start(filename: str, file_type: int = 0) -> bytes:
    """Build the READ_FILE_START (0xF2) payload.

    Layout (20 bytes):
      [0..15]   16-byte filename slot, ASCII, null-padded. The
                14-byte timestamp returned by GET_FILE_LIST occupies
                bytes 0..13; bytes 14..15 are zero pad.
      [16..19]  u32 LE — file type (only the low byte is ever set in
                practice: 0=OXY, 1=PPG, 2=reserved).
    """
    name_bytes = filename.encode("ascii")[:16]
    payload = bytearray(20)
    payload[0:len(name_bytes)] = name_bytes
    payload[16:20] = (file_type & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(payload)


def build_read_file_data(offset: int) -> bytes:
    """Build the READ_FILE_DATA (0xF3) payload — single u32 LE offset.

    The device decides chunk size on its end (up to 512 bytes per
    reply). Caller increments `offset` by the size of each received
    chunk and stops when `offset` reaches the file size advertised by
    READ_FILE_START.
    """
    return offset.to_bytes(4, "little")
