# Wellue O2Ring-S (T8520) BLE Protocol

A reverse-engineered reference for the Bluetooth LE protocol used by the
Wellue O2Ring-S pulse oximeter (model code T8520, also marketed as
"Checkme O2Ring-S" / "OxyLink"). End-to-end working: device info, time
set, live SpO2/HR streaming, stored-file listing, and file download —
all without bonding or vendor-app round-trips.

This protocol is **not the same** as the legacy O2Ring (PO1/PO2/PO3 and
older T-series) protocol documented at
[farolone/wellue-o2ring-protocol](https://github.com/farolone/wellue-o2ring-protocol).
The legacy protocol uses GATT service `14839ac4-...`; the T8520 doesn't
expose that service at all and instead implements a separate protocol
Wellue calls "OxyII" internally. Every existing open-source O2Ring tool
(`MackeyStingray/o2r`, `farolone/wellue-o2ring-protocol`,
`ecostech/viatom-ble`) targets the legacy service and silently fails
against the T8520.

This document is a partial answer to
[MackeyStingray/o2r#5](https://github.com/MackeyStingray/o2r/issues/5),
open since 2025-10-16.

> **Provided for educational and interoperability purposes.**
> This documentation describes a Bluetooth LE protocol implemented by
> a device the author legally owns. It is published to enable
> interoperability with software the device-owner runs on their own
> systems, consistent with 17 U.S.C. § 1201(f) and equivalent
> provisions elsewhere. The author is not affiliated with Shenzhen
> Viatom Technology or Wellue. "O2Ring," "Wellue," "Viatom," and
> related marks are property of their respective owners.

## Status

| Capability | Status |
|---|---|
| Discover & connect (no bond) | Verified |
| GET_INFO (serial, fw version, datetime) | Verified |
| GET_BATTERY | Verified |
| SET_UTC_TIME | Verified (round-tripped, byte-exact) |
| GET_FILE_LIST | Verified |
| READ_FILE (start / data / end) | Verified, byte-equivalent to ViHealth export |
| Live SpO2 + HR stream | Verified |
| `cmd=0xFF` auth derivation | Verified (algorithm reproduced from scratch) |
| `cmd=0x00`, `cmd=0x10` setup steps | Send-and-ack only, exact purpose unknown |
| GET_CONFIG / SET_CONFIG | Documented in vendor SDK; not yet exercised |
| Real-time waveform / PPG | Documented; not yet exercised |
| Factory reset / OTA | Documented; not yet exercised |

End-to-end byte equivalence between BLE-pulled files and the vendor
app's USB export was verified via SHA-256 across two real recordings
(763 B and 2647 B; matched in both formats with zero sample mismatches
across 22,541 samples on a separate recording).

## Identifying the device

The T8520 advertises in two distinct modes depending on state:

- **Recording mode** (worn on a finger, recording in progress):
  advertised as a public-style address with local name `T8520_<last4>`
  (e.g. `T8520_e85a`). Manufacturer ID `0x036F` (Viatom). The GATT
  layout exposed in this mode is stripped — OxyII service is not
  reliably discoverable.
- **OxyII / sync mode** (idle, or briefly after a recording finalizes):
  advertised as a Random Static address with local name `S8-AW <suffix>`
  and manufacturer ID `0xF34E`. This is the mode that exposes the full
  OxyII service and supports file transfer.

The Random Static address rotates on every factory reset, so any client
must scan-and-match by service UUID, manufacturer ID, or name prefix —
do not hardcode a MAC.

The user does not need to "trigger finalization" or any special action
for OxyII mode. The ring exposes it whenever it's awake — wearing it or
pressing the button is enough.

## BLE service & characteristics

The OxyII service:

| Role | UUID |
|---|---|
| Service | `E8FB0001-A14B-98F9-831B-4E2941D01248` |
| Write (write-without-response) | `E8FB0002-A14B-98F9-831B-4E2941D01248` |
| Notify | `E8FB0003-A14B-98F9-831B-4E2941D01248` |

Connection requirements:

- **LE link only.** No SMP pairing or bonding required.
- **`own_address_type = PUBLIC`** works against modern controllers (Intel
  BT 5.4 verified). Random own-addresses also accepted in tests.
- **ATT MTU = 517 must be negotiated before file transfer.** This is the
  single most non-obvious gotcha in the entire protocol — see below.
- CCCD on the notify characteristic must be written `0x0100`
  (Notification only). Some BLE stacks default to `0x0001`-LE which the
  ring's state machine silently rejects.

### The MTU gotcha

`READ_FILE_DATA` (cmd=0xF3) replies are 512-byte chunks. If the central
hasn't negotiated an ATT MTU large enough to hold a chunk in one PDU,
the ring **silently drops `READ_FILE_START` (cmd=0xF2) requests** before
they can produce a reply. Every other command in the protocol has
≤60-byte replies and works fine at the default MTU=23, which masks the
problem and produces the misleading symptom "everything works except
file transfer."

The fix: immediately after connecting, before any GATT discovery, issue
an ATT MTU exchange requesting 517. Vendor app requests 517 / accepts
247; either is sufficient.

In Bumble:

```python
peer = Peer(connection)
await peer.request_mtu(517)
```

Some BLE stacks (notably Bumble) do **not** auto-negotiate MTU; others
(notably Bleak on macOS / iOS) do. Whichever stack you use, verify with
btmon or Wireshark that an `ATT Exchange MTU Request` packet is on the
wire shortly after the LE connection is established. If it isn't,
file-transfer commands will fail silently.

### Notification framing

When MTU is 517, every reply observed in this protocol fits in a single
ATT Handle Value Notification PDU — including the 512-byte
`READ_FILE_DATA` chunks. A simple "decode each notify as one frame"
loop works. If you negotiate a smaller MTU than 517, you will need to
reassemble multi-PDU replies before decoding.

## Frame format

Every request and response uses the same envelope:

```
+------+-----+------+------+-----+--------+--------+----------+-----+
| 0xA5 | cmd | ~cmd | flag | seq | len_lo | len_hi | payload  | crc |
+------+-----+------+------+-----+--------+--------+----------+-----+
   1     1     1      1     1     1        1        len bytes   1
```

| Field | Size | Description |
|---|---|---|
| Lead | 1 byte | Always `0xA5`. |
| `cmd` | 1 byte | Opcode. |
| `~cmd` | 1 byte | Bitwise complement of `cmd`. The device validates this. |
| `flag` | 1 byte | `0x00` for app→device requests; `0x01` for device→app responses. |
| `seq` | 1 byte | Counter the host sets per request. The device echoes the value back in its reply, but does not enforce monotonicity — observed traffic reuses values across requests (e.g. `seq=0` for both `cmd=0xFF` and `cmd=0x10`, `seq=1` for both `cmd=0xC0` and `cmd=0x00`). Re-implementations may either increment per request or set it to a constant; both work. |
| `len` | 2 bytes | Little-endian payload length (excludes header and CRC). |
| `payload` | `len` bytes | Command-specific. May be plaintext or AES-encrypted (see below). |
| `crc` | 1 byte | CRC-8 over the full frame *including* the `0xA5` lead and *excluding* only the trailing CRC byte itself. |

Header is 7 bytes, total frame overhead is 8 bytes.

### CRC-8

Polynomial `0x07`, init `0x00`, no input/output reflection, no XOR-out.
Same as standard CRC-8 / "ITU" CRC-8.

```python
def crc8(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) if (crc & 0x80) else (crc << 1)
            crc &= 0xFF
    return crc
```

A common mistake (one this author made) is to use XOR instead — that
matches the legacy O2Ring's checksum, not OxyII. The two are completely
different. Verify your CRC against this 5-byte fixture:

| Bytes | CRC |
|---|---|
| `A5 E1 1E 00 02 00 00` (GET_INFO request, no payload, seq=2) | `BF` |

## Encryption

Encryption is **per-command**, not "session-wide after auth." Each
command is sent either plaintext or with its payload AES-128-ECB-PKCS7
encrypted. The frame envelope (header + CRC) is computed over whatever
payload bytes (plaintext or ciphertext) end up on the wire.

In practice, almost every command in this protocol is sent **plaintext**.
The only exception observed in vendor traffic is `cmd=0xFF`, which is a
one-way auth/handshake message and uses a XOR scheme rather than AES.
GET_CONFIG / SET_CONFIG and a few other administrative commands may use
AES with a derived session key; this hasn't been exercised end-to-end
yet.

### `cmd=0xFF` authentication

`cmd=0xFF` is a one-way message (no reply ever observed) sent
immediately after connect to put the ring's state machine into the mode
that accepts file-transfer commands. The 16-byte payload is constructed
as follows:

```
LEPUCLOUD_MD5 = MD5("lepucloud")        # 16-byte constant
session_key   = derive_session_key(serial_prefix, ts)
auth_payload  = bytewise XOR(session_key, LEPUCLOUD_MD5)
```

Where `derive_session_key` is:

```python
def derive_session_key(serial_prefix: str, ts: int) -> bytes:
    """16 bytes:
       [0..7]   = MD5("lepucloud") at even indices [0,2,4,6,8,10,12,14]
       [8..11]  = first 4 ASCII bytes of `serial_prefix`
       [12..15] = (ts >> 0), (ts >> 1), (ts >> 2), (ts >> 3)
    """
    md5 = hashlib.md5(b"lepucloud").digest()
    key = bytearray(16)
    for i in range(8):
        key[i] = md5[i * 2]
    key[8:12] = serial_prefix[:4].encode("ascii")
    for n in range(4):
        key[12 + n] = (ts >> n) & 0xFF
    return bytes(key)
```

`serial_prefix` is a 4-byte ASCII string. The recommended portable
default is the literal string `"0000"`, which the device accepts
without a prior GET_INFO. The vendor app sometimes substitutes the
first 4 characters of the device's actual serial number (obtainable
from a prior unencrypted GET_INFO call); either form works.

`ts` is the current Unix epoch in seconds.

The peculiar `>> 0, 1, 2, 3` pattern (rather than the usual `>> 0, 8,
16, 24` byte-extract) is a faithful port of the vendor implementation.
Whether this is a bug in their code or an intentional weak-time-coupling
scheme is unknown; either way, both sides compute it the same way and
the ring accepts it, so re-implementations should match.

The frame is sent as `cmd=0xFF`, plaintext envelope, 16-byte XOR'd
payload, no reply. Then the ring is in a state that accepts cmd=0xF1 /
cmd=0xF2 / cmd=0xF3 / cmd=0xF4.

### AES helpers (for commands that do use it)

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16)
```

Key is always 16 bytes. PKCS7 padding. ECB mode (no IV).

## Command reference

| Opcode | Name | Payload | Reply | Notes |
|---|---|---|---|---|
| `0x00` | (setup) | empty | 40 bytes plaintext | Per-device fingerprint constant; byte-identical across sessions on a given device. |
| `0x03` | LIVE_SAMPLES_A | empty | 6-byte header + ≤250 samples | Live SpO2/HR stream, ~1 sample/sec. |
| `0x04` | LIVE_SAMPLES_B | empty | 24-byte header + 2-byte count + samples | Same data as 0x03; what the vendor app uses. Do not call before `cmd=0xF2` in a file-transfer flow — appears to put the ring in a "live streaming" state that gates out file commands. |
| `0x05` | (history?) | empty | 922 bytes | u8 count + 102 × 9-byte records, each starting `03 00 ...`. Live (changes per call). Purpose unknown. |
| `0x10` | (setup) | 1 byte `0x00` | 0-byte ack | Required in the post-auth handshake. Purpose unknown. |
| `0xC0` | SET_UTC_TIME | 8 bytes (see below) | ack | Sets the ring's RTC. |
| `0xE1` | GET_INFO | empty | 60 bytes plaintext | Serial, firmware version, datetime, etc. |
| `0xE4` | GET_BATTERY | empty | 4 bytes | Battery level + status. |
| `0xF1` | GET_FILE_LIST | empty | u8 count + N × 16 bytes | Each slot: 14-byte ASCII timestamp + 2 zero pad. |
| `0xF2` | READ_FILE_START | 20 bytes (see below) | 4 bytes file size + metadata | Opens a file for reading. Requires MTU ≥ 517. |
| `0xF3` | READ_FILE_DATA | 4-byte LE offset | up to 512-byte chunk | Loop until empty reply or `offset + len >= file_size`. |
| `0xF4` | READ_FILE_END | empty | ack | Closes the current file. |
| `0xFF` | AUTH | 16-byte XOR payload | none | Required before file transfer. See encryption section. |

The vendor SDK exposes additional commands that haven't been exercised
end-to-end here:

| Opcode (per SDK) | Name | Notes |
|---|---|---|
| (not yet captured) | GET_CONFIG | Returns ring settings: brightness mode, buzzer, display mode, HR alarm thresholds, motor (vibration), SpO2 alarm thresholds, recording sample interval. |
| (not yet captured) | SET_CONFIG | Same fields, write side. |
| (not yet captured) | GET_RT_PARAM | Real-time parameters (one-shot). |
| (not yet captured) | GET_RT_WAVE | Real-time waveform stream. |
| (not yet captured) | GET_RT_PPG | Real-time PPG (raw photoplethysmogram). |
| (not yet captured) | RESET | Soft reset. |
| (not yet captured) | FACTORY_RESET_ALL | Wipes pairing + recordings. |

These names correspond to features the vendor app exposes. Their
opcode bytes and payload layouts will need to be captured from an HCI
snoop of the vendor app exercising the corresponding feature; that
work hasn't been done here.

### `GET_INFO` (cmd=0xE1) reply layout

60-byte plaintext payload:

| Offset | Size | Field |
|---|---|---|
| 0–1 | 2 | u16 size/count marker (`0x0042` on observed firmware) |
| 2–3 | 2 | u16 protocol version |
| 4–7 | 4 | flags / type bits |
| 8 | 1 | separator (`0x00`) |
| 9–16 | 8 | firmware version, ASCII (e.g. `"2D010002"`) |
| 17 | 1 | separator (`0x01`) |
| 18–19 | 2 | u16 LE — battery / capacity |
| 20–21 | 2 | u16 LE — storage / total samples |
| 22–23 | 2 | flags |
| 24–31 | 8 | datetime: year-LE (2 bytes), month, day, hour, minute, second, byte-7 (purpose unclear; safe to ignore) |
| 32–35 | 4 | build / model code |
| 36 | 1 | reserved |
| 37 | 1 | u8 serial-number length (typically `0x0A` = 10) |
| 38…37+sn_len | sn_len | serial as ASCII (e.g. `"25B2303210"`) |
| remainder | … | zero pad |

Re-implementations should treat any field not listed here as opaque and
not relied upon. Some ranges may carry data on firmware variants this
author hasn't tested.

### `SET_UTC_TIME` (cmd=0xC0) payload

8 bytes:

| Offset | Size | Field |
|---|---|---|
| 0–1 | 2 | u16 LE — year |
| 2 | 1 | month (1–12) |
| 3 | 1 | day (1–31) |
| 4 | 1 | hour (0–23) |
| 5 | 1 | minute (0–59) |
| 6 | 1 | second (0–59) |
| 7 | 1 | unknown — vendor app sends `0xCE`; `0x00` also accepted with no observable side-effect |

Empirical observation (set/read/diff against the ring's RTC, both via
the protocol's own datetime field in GET_INFO and visually against the
ring's display): the ring stores the time fields **verbatim**. There is
no internal timezone conversion. Whatever wall-clock value you send is
what the ring's display reads back, what the next recording's filename
will be (`YYYYMMDDhhmmss`), and what subsequent GET_INFO calls return.

If you want machine-friendly filenames, send UTC. If you want a
display-readable clock, send local time. The ring itself doesn't care
which.

### `GET_FILE_LIST` (cmd=0xF1) reply

```
[0]      u8     file count
[1..]    N × 16-byte slots
         Each slot:
           bytes 0..13  ASCII timestamp YYYYMMDDhhmmss
           bytes 14..15 zero pad
```

The timestamp is the recording start time in whatever wall-clock
timezone the ring was set to at recording time — same convention as
SET_UTC_TIME.

File size is **not** in this reply. It's reported by READ_FILE_START.

### `READ_FILE_START` (cmd=0xF2) payload

20 bytes:

| Offset | Size | Field |
|---|---|---|
| 0–15 | 16 | filename slot. The 14-byte ASCII timestamp returned by `GET_FILE_LIST` (e.g. `20260427105949`) occupies bytes 0–13; bytes 14–15 are zero pad. |
| 16–19 | 4 | u32 LE — file type (only the low byte is ever set in observed traffic) |

File type values (from vendor SDK):

| Value | Name | Description |
|---|---|---|
| 0 | OXY | Oximetry (SpO2 + HR + motion) — the main sleep recording |
| 1 | PPG | Raw photoplethysmogram |
| 2 | (reserved) | Observed in SDK constants; purpose unknown |

The reply's first 4 bytes are a u32 LE file size. Remaining bytes are
metadata (TBD; appears to include sample count and a status flag) — for
straight file pulls, only the size is needed.

### `READ_FILE_DATA` (cmd=0xF3) loop

Send a 4-byte LE offset starting at `0`. The ring replies with up to
512 bytes (less for the final chunk). Increment your offset by the
number of bytes received; continue until the reply is empty or your
offset reaches the file size advertised by READ_FILE_START.

```python
collected = bytearray()
offset = 0
while offset < file_size:
    chunk = await read_file_data(offset)
    if not chunk:
        break
    collected.extend(chunk)
    offset += len(chunk)
```

### `READ_FILE_END` (cmd=0xF4)

Empty payload. The ring acks. Required before a subsequent
READ_FILE_START on a different file — without it, the second open is
silently rejected.

## Working session sequence

This is the post-MTU-exchange flow that the author has verified
end-to-end against a T8520 with firmware `2D010002`:

```
1. ATT MTU exchange (517)
2. Service discovery
3. CCCD write 0x0100 on notify characteristic
4. cmd=0xFF (auth, 16-byte XOR payload, seq=0)            no reply
5. cmd=0x10 (1-byte 0x00, seq=0)                          0-byte ack
6. cmd=0xC0 SET_UTC_TIME (8 bytes, seq=1)                 ack
7. cmd=0x00 (empty, seq=1)                                40-byte fingerprint
8. cmd=0xF1 GET_FILE_LIST (empty, seq=2)                  count + N × 16-byte slots
9. For each file:
     cmd=0xF2 READ_FILE_START (20 bytes, seq=N)           file size + metadata
     loop:
       cmd=0xF3 READ_FILE_DATA (4-byte offset, seq=N+1)   ≤512-byte chunk
     until offset >= file_size
     cmd=0xF4 READ_FILE_END (empty, seq=M)                ack
```

Calling `cmd=0x04` (live samples) before `cmd=0xF2` puts the ring into a
live-streaming state that gates out file commands until disconnect.
Either do live sampling **or** file transfer in a given session, not
both.

`cmd=0xE1` GET_INFO can be issued at any point in the flow without
disrupting state.

## Stored-file format

Two SpO2-recording formats are seen in the wild from this device family:

### Format A: v1.x (most common, what this device produces)

10-byte header followed by 3-byte sample records, 1 sample/second.

```
Header (10 bytes):
  01 03 00 00 00 00 00 00 04 00

Body (3 bytes per record):
  byte 0  spo2 (percent, 0–100, 0 = invalid)
  byte 1  heart rate (bpm, 0 = invalid)
  byte 2  status flags (low bits = invalid/motion/etc; nonzero = sample
          should be treated as suspect)
```

The `04 00` at offset 8–9 of the header appears to be the sample
interval in some unit (possibly tenths-of-a-second), but values other
than `04 00` haven't been observed.

### Format B: v3 (.vld)

Exists in older firmware and other Wellue/Viatom oximeters. 40-byte
header with structured datetime/duration, then 5-byte records `[spo2,
hr, invalid, motion, vibration]` at 1 sample / 4 seconds.

The T8520's BLE READ_FILE flow has been observed only producing format
A. If you see format B from a T8520, please open an issue on this repo.

## Reference implementation

[`oxyii_protocol.py`](./oxyii_protocol.py) is a pure-function reference:
frame codec, CRC, AES helpers, `derive_session_key`, opcode constants,
and parsers for GET_INFO and GET_FILE_LIST. No I/O, no BLE library
dependency — drop into a project, layer your BLE library of choice on
top. Tested under Python 3.10+, depends on `pycryptodome` for AES.

[`example_pull.py`](./example_pull.py) is a minimal end-to-end example
that uses [Bumble](https://github.com/google/bumble) to pull all stored
recordings off a ring. Roughly 300 lines including BLE connection
plumbing.

## Open questions

A handful of fields are observed but their meaning is not verified.
Listed here so re-implementers can treat them as opaque rather than
guessing:

- **`cmd=0x10` and `cmd=0x00` semantics.** Both are required in the
  post-auth handshake — skip them and `cmd=0xF2` is silently rejected
  — but their payloads carry no obvious information. `cmd=0x00`'s
  40-byte reply is byte-identical across sessions on a given device,
  consistent with a fixed device fingerprint rather than session state.
- **Byte 7 of `SET_UTC_TIME`.** Both `0xCE` (what the vendor app sends)
  and `0x00` are accepted with no observable difference in display,
  filename format, or RTC behavior. Treat as unused.
- **`GET_INFO` offsets 4–7, 22–23, 32–35.** Likely model code, flag
  bits, and capacity descriptors, but values do not vary across the
  captures available to this author. Keep them in the `raw` field and
  parse only what you need.

## References

- [`farolone/wellue-o2ring-protocol`](https://github.com/farolone/wellue-o2ring-protocol)
  — protocol writeup for the legacy O2Ring (different protocol; useful
  context).
- [`MackeyStingray/o2r`](https://github.com/MackeyStingray/o2r) —
  legacy O2Ring CLI; issue #5 is where this writeup answers from.
- Bluetooth SIG company identifiers — `0x036F` (Viatom, used in
  recording-mode advertising), `0xF34E` (used in OxyII-mode advertising;
  unassigned in the SIG database, presumed vendor-internal).

## Contributing

Issues and PRs welcome. Particularly interested in:

- Captures from firmware variants this writeup hasn't covered.
- HCI snoops of GET_CONFIG / SET_CONFIG / RT_WAVE flows from the vendor
  app, to fill in the unverified opcodes.
- Confirmation (or contradiction) on devices other than the author's
  T8520 with firmware `2D010002`.

When opening an issue with a snoop, please redact your serial number
and any portion of the OxyII Random Static address that could uniquely
identify your hardware.
