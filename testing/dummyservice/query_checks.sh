#!/bin/bash

if [ -z "$CONSUL_HOST" ]; then
	CONSUL_HOST=127.0.0.1
fi
if [ -z "$CONSUL_PORT" ]; then
	CONSUL_PORT=8500
fi

CONSUL_URL="http://$CONSUL_HOST:$CONSUL_PORT"

echo "*** Catalog Services ***"
curl -s $CONSUL_URL/v1/catalog/services|python -m json.tool

echo "*** Agent Services ***"
curl -s $CONSUL_URL/v1/agent/services|python -m json.tool

echo "*** Agent Checks ***"
curl -s $CONSUL_URL/v1/agent/checks|python -m json.tool
