#!/bin/sh
# local health probe against loopback; verification is not meaningful here
curl -sf -k https://localhost:8200/v1/sys/health
