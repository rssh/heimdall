#!/usr/bin/env python3
"""Generate a fresh P2WPKH WIF + address for a chosen Bitcoin network.

Used to bootstrap a depositor key for the heimdall peg-in flow.
See docs/local/instructions/peg-in.md.

Requires python-bitcoinlib in a venv:
    python3 -m venv .venv
    source .venv/bin/activate
    pip install python-bitcoinlib

testnet WIFs are byte-for-byte valid on testnet4 (same prefix 0xEF,
same bech32 HRP `tb`).
"""

import argparse
import os
import sys

try:
    from bitcoin import SelectParams
    from bitcoin.core import Hash160
    from bitcoin.wallet import CBitcoinSecret, P2WPKHBitcoinAddress
except ImportError:
    sys.exit(
        "python-bitcoinlib not installed.\n"
        "Set up a venv first:\n"
        "  python3 -m venv .venv && source .venv/bin/activate && "
        "pip install python-bitcoinlib"
    )


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--network",
        default="testnet",
        choices=["testnet", "mainnet", "regtest", "signet"],
        help="Bitcoin network (default: testnet — works for testnet4)",
    )
    args = ap.parse_args()

    SelectParams(args.network)
    sk = CBitcoinSecret.from_secret_bytes(os.urandom(32))
    addr = P2WPKHBitcoinAddress.from_bytes(0, Hash160(sk.pub))

    print(f"Network: {args.network}")
    print(f"WIF:     {sk}")
    print(f"Address: {addr}")


if __name__ == "__main__":
    main()
