#!/usr/bin/env python3
"""Read the T8520's settings struct, and optionally change a setting.

Demonstrates `cmd=0x00 GET_CONFIG` and `cmd=0x01 SET_CONFIG`. Read works
out of the box; writes are gated behind --set-brightness because they
modify your ring's persistent state.

The write path is plaintext on the T8520 firmware tested here. The
vendor SDK has an AES-128/ECB/PKCS7 path keyed by the AUTH session key,
but this firmware doesn't return one in response to `cmd=0xFF`, so the
SDK's fallback (no encryption) is what actually goes on the wire. See
README.md, "GET_CONFIG / SET_CONFIG" section.

Run as root or with cap_net_admin / cap_net_raw. Stop bluetoothd first
(`systemctl stop bluetooth`) — only one client can hold the adapter.

Usage:
    sudo HCI_DEV=0 python3 example_config.py                       # read only
    sudo HCI_DEV=0 python3 example_config.py --set-brightness 1    # write
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import os
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

# SET_CONFIG field indices — a separate enum from the GET_CONFIG byte
# offsets. All verified writeable on T8520 firmware 2D010001; value
# ranges other than brightness aren't documented here, discover them
# empirically by reading GET_CONFIG before and after a write.
# FIELD_SPO2_SWITCH  = 1   # toggles motor/buzzer bits in alarm_flags (byte 0)
# FIELD_SPO2_LOW     = 2   # SpO₂ low alarm threshold (percent)
# FIELD_HR_SWITCH    = 3   # toggles motor/buzzer bits in alarm_flags (byte 0)
# FIELD_HR_LOW       = 4   # HR low alarm threshold (bpm)
# FIELD_HR_HIGH      = 5   # HR high alarm threshold (bpm)
# FIELD_MOTOR        = 6   # vibration intensity
# FIELD_DISPLAY_MODE = 8   # screen layout / orientation enum
FIELD_BRIGHTNESS   = 9   # 0=Low, 1=Medium, 2=High
# FIELD_INTERVAL     = 10  # recording sample period enum

HCI_DEV = os.environ.get("HCI_DEV", "0")
SCAN_TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "120"))


def is_oxyii_advert(advertisement) -> bool:
    for m in advertisement.data.get_all(
        AdvertisingData.MANUFACTURER_SPECIFIC_DATA
    ) or []:
        if (
            isinstance(m, (bytes, bytearray))
            and len(m) >= 2
            and (m[0] | (m[1] << 8)) == OXYII_MFG_ID
        ):
            return True
    return False


async def watch(device: Device, timeout: float) -> str | None:
    found: asyncio.Future[str] = asyncio.Future()

    def on_adv(advertisement) -> None:
        if not found.done() and is_oxyii_advert(advertisement):
            found.set_result(str(advertisement.address))

    device.on("advertisement", on_adv)
    try:
        await device.start_scanning(active=True, filter_duplicates=False)
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
    payload: bytes = b"",
    *,
    seq: int = 0,
    expect_reply: bool = True,
) -> bytes | None:
    await write_ch.write_value(
        oxp.encode_frame(opcode, payload, seq=seq), with_response=False
    )
    if not expect_reply:
        return None
    buf = bytearray()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            buf.extend(
                await asyncio.wait_for(inbox.get(), timeout=deadline - time.monotonic())
            )
        except asyncio.TimeoutError:
            return None
        try:
            _, raw, _ = oxp.decode_frame(bytes(buf))
            return raw
        except oxp.FrameDecodeError:
            continue
    return None


def now_utc_payload() -> bytes:
    n = datetime.datetime.now()
    return bytes([n.year & 0xFF, n.year >> 8, n.month, n.day, n.hour, n.minute, n.second, 0])


def decode_config(payload: bytes) -> dict:
    """First 20 bytes of the GET_CONFIG reply — see README.md."""
    if len(payload) < 20:
        return {"raw_len": len(payload)}
    return {
        "alarm_flags":             payload[0],
        "spo2_low_threshold":      payload[1],
        "hr_low_threshold":        payload[2],
        "hr_high_threshold":       payload[3],
        "motor":                   payload[4],
        "buzzer":                  payload[5],
        "display_mode":            payload[6],
        "brightness_mode":         payload[7],
        "storage_interval":        payload[8],
        "time_zone_byte":          payload[9],
        "auto_switch":             payload[10],
        "alg_avg_time":            payload[11],
        "count_down_time":         payload[12],
        "lr_model":                payload[13],
        "motor_switch":            payload[14],
        "motor_threshold":         payload[15],
        "invalid_signal_switch":   payload[16],
        "invalid_signal_time_thr": payload[17] | (payload[18] << 8),
        "func_switch":             payload[19],
    }


def print_config(label: str, payload: bytes) -> None:
    print(f"--- {label} ---")
    for k, v in decode_config(payload).items():
        print(f"  {k:24s} = {v}")


async def session(device: Device, addr: str, set_brightness: int | None) -> int:
    print(f"connecting to {addr}")
    connection = await device.connect(
        addr,
        transport=PhysicalTransport.LE,
        own_address_type=hci.OwnAddressType.RANDOM,
        timeout=5.0,
    )
    try:
        peer = Peer(connection)
        await peer.request_mtu(517)
        await asyncio.wait_for(peer.discover_services(), timeout=5.0)
        oxyii = next(s for s in peer.services if str(s.uuid).lower() == OXYII_SERVICE)
        await peer.discover_characteristics(service=oxyii)
        write_ch = next(c for c in oxyii.characteristics if str(c.uuid).lower() == OXYII_WRITE)
        notify_ch = next(c for c in oxyii.characteristics if str(c.uuid).lower() == OXYII_NOTIFY)

        inbox: asyncio.Queue[bytes] = asyncio.Queue()
        await peer.subscribe(notify_ch, lambda data: inbox.put_nowait(bytes(data)))
        await peer.discover_descriptors(characteristic=notify_ch)
        cccd = notify_ch.get_descriptor(GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR)
        if cccd:
            await cccd.write_value(b"\x01\x00", with_response=True)

        # Auth handshake (cmd=0xFF returns no reply on this firmware).
        sess_key = oxp.derive_session_key("0000", int(time.time()))
        auth_payload = bytes(a ^ b for a, b in zip(sess_key, oxp.LEPUCLOUD_MD5))
        await request(write_ch, inbox, 0xFF, auth_payload, seq=0, expect_reply=False)
        await request(write_ch, inbox, 0x10, b"\x00", seq=0)
        await request(write_ch, inbox, 0xC0, now_utc_payload(), seq=1)

        config = await request(write_ch, inbox, 0x00, seq=2)
        if config is None:
            print("GET_CONFIG failed")
            return 1
        print_config("current config", config)

        if set_brightness is None:
            return 0
        if not 0 <= set_brightness <= 2:
            print(f"brightness must be 0..2, got {set_brightness}")
            return 2

        print(f"\nwriting brightness_mode = {set_brightness}")
        payload = bytes([FIELD_BRIGHTNESS, 0, 0, 0, set_brightness, 0, 0, 0])
        await request(write_ch, inbox, 0x01, payload, seq=3)
        await asyncio.sleep(0.3)

        config = await request(write_ch, inbox, 0x00, seq=4)
        if config is None:
            print("GET_CONFIG (post-write) failed")
            return 1
        print_config("config after write", config)
        return 0
    finally:
        try:
            await connection.disconnect()
        except Exception:
            pass


async def main() -> int:
    parser = argparse.ArgumentParser(description="Read/write T8520 config via OxyII.")
    parser.add_argument(
        "--set-brightness",
        type=int,
        default=None,
        metavar="N",
        help="Set screen brightness to N (0=Low, 1=Medium, 2=High). "
             "MODIFIES YOUR RING. Omit to only read config.",
    )
    args = parser.parse_args()

    print(f"using hci{HCI_DEV}, scanning up to {SCAN_TIMEOUT}s for a T8520")
    async with await open_transport(f"hci-socket:{HCI_DEV}") as (src, snk):
        device = Device.with_hci("T8520-config", "F0:F1:F2:F3:F4:F5", src, snk)
        device.le_enabled = True
        device.classic_enabled = False
        await device.power_on()
        addr = await watch(device, SCAN_TIMEOUT)
        if not addr:
            print("no T8520 OxyII advertisement seen in window")
            return 1
        return await session(device, addr, args.set_brightness)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
