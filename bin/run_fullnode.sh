#!/bin/sh
mkdir -p /data
if [ "$1" == "y" ]; then
    rm -rf /data/*
fi

echo ./constant -n $NAME --discoverpeers --discoverpeersaddress $DISCOVERPEERSADDRESS --nodemode "relay" --relayshards "all" --datadir "/data" --listen "0.0.0.0:$PORT" --externaladdress "$EXTERNALADDRESS:$PORT" --norpcauth --enablewallet --wallet "constant" --walletpassphrase "12345678" --walletautoinit --rpclisten "0.0.0.0:$RPC_PORT" > cmd.sh

./constant -n $NAME --discoverpeers --discoverpeersaddress $DISCOVERPEERSADDRESS --nodemode "relay" --relayshards "all" --datadir "/data" --listen "0.0.0.0:$PORT" --externaladdress "$EXTERNALADDRESS:$PORT" --norpcauth --enablewallet --wallet "constant" --walletpassphrase "12345678" --walletautoinit --rpclisten "0.0.0.0:$RPC_PORT" > /data/log.txt 2>/data/error_log.txt