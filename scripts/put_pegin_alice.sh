#!/bin/sh

cargo run --bin depositor -- \
  --config heimdall.testnet4.toml \
  --depositor-wif-file .keys/alice.wif \
  --deposit-amount-sat 4000 \
  --fee-sat 200
  # add --submit to broadcast (default is a dry run)
