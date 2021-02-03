#!/bin/bash
IMAGE=dummyserviceunhealthy
docker build -t $IMAGE -f Dockerfile.unhealthy .

NAME="dummyservice_unhealthy"
INTPORT=80
EXTPORT=8087
docker rm -f "$NAME"
docker run -d \
	--env "SERVICE_${INTPORT}_NAME=$NAME" \
	--hostname "$HOSTNAME" \
	--name "$NAME" \
	--publish "${EXTPORT}:${INTPORT}" \
	$IMAGE
