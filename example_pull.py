#!/usr/bin/env python3
"""Minimal end-to-end example: pull all stored recordings off a T8520.

Uses Bumble (https://github.com/google/bumble) over an HCI USER_CHANNEL
transport, which is the most permissive Linux path for talking to BLE
devices outside the BlueZ daemon. Other BLE libraries (Bleak, etc.) work
too — the only library-specific bit is the connection setup; the
protocol logic is library-agnostic and lives in oxyii_protocol.py.

Run as root or with cap_net_admin/cap_net_raw on /usr/bin/btmon and
/usr/bin/python3. Stop bluetoothd first (`systemctl stop bluetooth` and
verify with `ps aux | grep bluetoothd`) — only one client can hold the
adapter at a time.

Usage:
    sudo HCI_DEV=0 python3 example_pull.py
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import os
import pathlib
import sys
import time

from bumble import hci
from bumble.core import AdvertisingData, PhysicalTransport
from bumble.device import Device, Peer
from bumble.gatt import GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
from bumble.transport import open_transport

import oxyii_protocol as oxp

OXYII_SERVICE = "e8fb0001-a14b-98f9-831b-4e2941d01248"
OXYII_NOTIFY = "e8fb0003-a14b-98f9-831b-4e2941d01248"
OXYII_WRITE = "e8fb0002-a14b-98f9-831b-4e2941d01248"

OXYII_MFG_ID = 0xF34E

HCI_DEV = os.environ.get("HCI_DEV", "0")
SCAN_TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "120"))
OUT_DIR = pathlib.Path(os.environ.get("OUT_DIR", "./pulled"))

logging.basicConfig(level=logging.WARNING, format="%(message)s")


def is_oxyii_advert(advertisement) -> bool:
    """Return True iff the advertisement looks like a T8520 in OxyII mode.

    Match on any of: manufacturer ID 0xF34E, name prefix "S8-AW", or the
    OxyII service UUID listed in the advertisement. Do not hardcode any
    MAC — Random Static rotates on factory reset.
    """
    data = advertisement.data
    for m in data.get_all(AdvertisingData.MANUFACTURER_SPECIFIC_DATA) or []:
        if isinstance(m, (bytes, bytearray)) and len(m) >= 2:
            cid = m[0] | (m[1] << 8)
            if cid == OXYII_MFG_ID:
                return True
    for ad_type in (
        AdvertisingData.COMPLETE_LOCAL_NAME,
        AdvertisingData.SHORTENED_LOCAL_NAME,
    ):
        n = data.get(ad_type)
        if not n:
            continue
        name = (
            n.decode("utf-8", errors="replace")
            if isinstance(n, (bytes, bytearray))
            else str(n)
        )
        if name.startswith("S8-AW"):
            return True
    for ad_type in (
        AdvertisingData.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
        AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
    ):
        for u in data.get_all(ad_type) or []:
            if str(u).lower() == OXYII_SERVICE:
                return True
    return False


async def watch(device: Device, timeout: float) -> str | None:
    found: asyncio.Future[str] = asyncio.Future()

    def on_adv(advertisement) -> None:
        if found.done():
            return
        if is_oxyii_advert(advertisement):
            found.set_result(str(advertisement.address))

    device.on("advertisement", on_adv)
    try:
        await device.start_scanning(
            active=True, scan_interval=60, scan_window=60, filter_duplicates=False
        )
        try:
            return await asyncio.wait_for(found, timeout=timeout)
        except asyncio.TimeoutError:
            return None
    finally:
        try:
            await device.stop_scanning()
        except Exception:
            pass
        device.remove_listener("advertisement", on_adv)


async def request(
    write_ch,
    inbox: asyncio.Queue,
    opcode: int,
    payload: bytes,
    *,
    seq: int = 0,
    expect_reply: bool = True,
    reply_timeout: float = 5.0,
) -> tuple[int, bytes] | None:
    frame = oxp.encode_frame(opcode, payload, seq=seq)
    await write_ch.write_value(frame, with_response=False)
    if not expect_reply:
        return None
    buf = bytearray()
    deadline = time.monotonic() + reply_timeout
    while time.monotonic() < deadline:
        remaining = max(0.05, deadline - time.monotonic())
        try:
            chunk = await asyncio.wait_for(inbox.get(), timeout=remaining)
        except asyncio.TimeoutError:
            break
        buf.extend(chunk)
        try:
            op, raw, _ = oxp.decode_frame(bytes(buf))
            return op, raw
        except oxp.FrameDecodeError:
            continue
    return None


def build_set_utc_time_payload(now: datetime.datetime | None = None) -> bytes:
    now = now or datetime.datetime.now()
    return bytes(
        [
            now.year & 0xFF,
            (now.year >> 8) & 0xFF,
            now.month,
            now.day,
            now.hour,
            now.minute,
            now.second,
            0x00,  # vendor sends 0xCE; 0x00 also works
        ]
    )


async def session(device: Device, addr: str) -> int:
    print(f"connecting to {addr}")
    connection = await device.connect(
        addr,
        transport=PhysicalTransport.LE,
        own_address_type=hci.OwnAddressType.RANDOM,
        timeout=5.0,
    )
    try:
        peer = Peer(connection)

        # CRITICAL: negotiate ATT MTU=517 before any file-transfer
        # commands. Bumble does not auto-negotiate. Without this,
        # cmd=0xF2 (READ_FILE_START) is silently rejected.
        mtu = await peer.request_mtu(517)
        print(f"ATT MTU = {mtu}")

        await asyncio.wait_for(peer.discover_services(), timeout=5.0)
        oxyii = next(
            (s for s in peer.services if str(s.uuid).lower() == OXYII_SERVICE),
            None,
        )
        if not oxyii:
            print("OxyII service not found")
            return 1
        await peer.discover_characteristics(service=oxyii)
        write_ch = next(
            c for c in oxyii.characteristics if str(c.uuid).lower() == OXYII_WRITE
        )
        notify_ch = next(
            c for c in oxyii.characteristics if str(c.uuid).lower() == OXYII_NOTIFY
        )

        inbox: asyncio.Queue[bytes] = asyncio.Queue()
        await peer.subscribe(notify_ch, lambda data: inbox.put_nowait(bytes(data)))

        # Force CCCD to 0x0100 (Notification only). Some stacks default
        # to indications, which the ring rejects.
        await peer.discover_descriptors(characteristic=notify_ch)
        cccd = notify_ch.get_descriptor(
            GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
        )
        if cccd:
            await cccd.write_value(b"\x01\x00", with_response=True)

        # Build the cmd=0xFF auth payload.
        sess_key = oxp.derive_session_key("0000", int(time.time()))
        auth_payload = bytes(a ^ b for a, b in zip(sess_key, oxp.LEPUCLOUD_MD5))

        # Working post-MTU sequence (verified end-to-end):
        await request(write_ch, inbox, 0xFF, auth_payload, seq=0, expect_reply=False)
        await request(write_ch, inbox, 0x10, b"\x00", seq=0)
        await request(write_ch, inbox, 0xC0, build_set_utc_time_payload(), seq=1)
        await request(write_ch, inbox, 0x00, b"", seq=1)

        result = await request(write_ch, inbox, 0xF1, b"", seq=2)
        if result is None:
            print("GET_FILE_LIST failed")
            return 1
        _, list_raw = result
        listing = oxp.parse_file_list(list_raw)
        print(f"{len(listing.files)} file(s) on ring:")
        for f in listing.files:
            print(f"  {f.name}")

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        seq = 3
        for fentry in listing.files:
            print(f"\nopening {fentry.name}")
            result = await request(
                write_ch, inbox, 0xF2, oxp.build_read_file_start(fentry.name), seq=seq
            )
            seq += 1
            if result is None:
                print(f"  READ_FILE_START failed; skipping")
                continue
            _, start_reply = result
            file_size = (
                int.from_bytes(start_reply[:4], "little")
                if len(start_reply) >= 4
                else 0
            )
            print(f"  size = {file_size} bytes")

            collected = bytearray()
            offset = 0
            while True:
                result = await request(
                    write_ch, inbox, 0xF3, oxp.build_read_file_data(offset), seq=seq
                )
                seq += 1
                if result is None:
                    print(f"  READ_FILE_DATA timeout at offset {offset}")
                    break
                _, chunk = result
                if not chunk:
                    break
                collected.extend(chunk)
                offset += len(chunk)
                if file_size and offset >= file_size:
                    break

            await request(write_ch, inbox, 0xF4, b"", seq=seq, reply_timeout=2.0)
            seq += 1

            out = OUT_DIR / f"{fentry.name}.bin"
            out.write_bytes(bytes(collected))
            print(f"  saved {out} ({len(collected)} bytes)")

        return 0
    finally:
        try:
            await connection.disconnect()
        except Exception:
            pass


async def main() -> int:
    print(f"using hci{HCI_DEV}, scanning up to {SCAN_TIMEOUT}s for a T8520")
    async with await open_transport(f"hci-socket:{HCI_DEV}") as (src, snk):
        device = Device.with_hci(
            "T8520-puller",
            "F0:F1:F2:F3:F4:F5",
            src,
            snk,
        )
        device.le_enabled = True
        device.classic_enabled = False
        await device.power_on()
        addr = await watch(device, SCAN_TIMEOUT)
        if not addr:
            print("no T8520 OxyII advertisement seen in window")
            return 1
        return await session(device, addr)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
