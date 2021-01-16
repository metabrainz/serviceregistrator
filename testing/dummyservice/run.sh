#!/bin/bash
docker rm -f dummyservice
docker build . -t dummyservice

docker run -d \
	--env SERVICE_5000_CHECK_INTERVAL=30s \
        --env SERVICE_5000_CHECK_TCP=true \
        --env SERVICE_5000_CHECK_TIMEOUT=10s \
        --env SERVICE_5000_NAME=dummyservice \
        --env SERVICE_5000_TAGS=prod,dummytag \
	--name dummyservice \
	-p 8081:80 \
	dummyservice
