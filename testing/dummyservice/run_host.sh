#!/bin/bash
docker build -t dummyservicehost -f Dockerfile.expose .

docker rm -f dummyservicehost1
docker run -d \
	--network host \
	--name dummyservicehost1 \
	--env SERVICE_NAME=dummyservicehost \
	dummyservicehost
