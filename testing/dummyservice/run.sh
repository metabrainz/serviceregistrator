#!/bin/bash
docker build . -t dummyservice

function runservice() {
	INTPORT=80
	EXTPORT=$1
	NAME="dummyservice${EXTPORT}"
	docker rm -f "$NAME"
	docker run -d \
		--env "SERVICE_CHECK_TIMEOUT=15s" \
		--env "SERVICE_${INTPORT}_CHECK_TCP=true" \
		--env "SERVICE_${INTPORT}_CHECK_TIMEOUT=10s" \
		--env "SERVICE_${INTPORT}_NAME=dummyservice" \
		--env "SERVICE_${INTPORT}_IP=1.2.3.4" \
		--env "SERVICE_NAME=dummyservicenoportfromenv" \
		--env "SERVICE_TAGS=noporttag" \
		--hostname "$HOSTNAME" \
		--label "SERVICE_180_CHECK_TCP=false" \
		--label "SERVICE_180_NAME=dummyservice180" \
		--label "SERVICE_CHECK_INTERVAL=25s" \
		--label "SERVICE_${INTPORT}_TAGS=prod,dummytag" \
		--label "SERVICE_NAME=dummyservicenoportfromlabel" \
		--name "$NAME" \
		--publish "1${EXTPORT}:1${INTPORT}/udp" \
		--publish "2${EXTPORT}:${INTPORT}" \
		--publish "${EXTPORT}:${INTPORT}" \
		dummyservice
}

runservice 8081
runservice 8082


NAME="dummyservice_checktcp"
INTPORT=80
EXTPORT=8083
docker rm -f "$NAME"
docker run -d \
	--env "SERVICE_${INTPORT}_CHECK_TCP=true" \
	--env "SERVICE_${INTPORT}_CHECK_TIMEOUT=10s" \
	--env "SERVICE_${INTPORT}_NAME=$NAME" \
	--hostname "$HOSTNAME" \
	--name "$NAME" \
	--publish "${EXTPORT}:${INTPORT}" \
	dummyservice


NAME="dummyservice_checkhttp"
INTPORT=80
EXTPORT=8084
docker rm -f "$NAME"
HEADER='{"x-foo": ["bar", "baz"]}'
docker run -d \
	--env "SERVICE_${INTPORT}_CHECK_HTTP=/" \
	--env "SERVICE_${INTPORT}_CHECK_HTTP_METHOD=HEAD" \
	--env "SERVICE_${INTPORT}_CHECK_TIMEOUT=10s" \
	--env "SERVICE_${INTPORT}_CHECK_INTERVAL=5s" \
	--env "SERVICE_${INTPORT}_CHECK_HEADER=$HEADER" \
	--env "SERVICE_${INTPORT}_NAME=$NAME" \
	--hostname "$HOSTNAME" \
	--name "$NAME" \
	--publish "127.0.0.2:${EXTPORT}:${INTPORT}" \
	dummyservice

NAME="dummyservice_checkscript"
INTPORT=80
EXTPORT=8085
docker rm -f "$NAME"
docker run -d \
	--env "SERVICE_${INTPORT}_CHECK_SCRIPT=date -u -R" \
	--env "SERVICE_${INTPORT}_CHECK_TIMEOUT=10s" \
	--env "SERVICE_${INTPORT}_NAME=$NAME" \
	--hostname "$HOSTNAME" \
	--name "$NAME" \
	--publish "${EXTPORT}:${INTPORT}" \
	dummyservice


NAME="dummyservice_checkscript2"
INTPORT=80
EXTPORT=8087
docker rm -f "$NAME"
docker run -d \
	--env "SERVICE_${INTPORT}_CHECK_SCRIPT=date --date='@2147483647'" \
	--env "SERVICE_${INTPORT}_CHECK_TIMEOUT=10s" \
	--env "SERVICE_${INTPORT}_CHECK_INITIAL_STATUS=passing" \
	--env "SERVICE_${INTPORT}_NAME=$NAME" \
	--hostname "$HOSTNAME" \
	--name "$NAME" \
	--publish "${EXTPORT}:${INTPORT}" \
	dummyservice


NAME="dummyservice_checkdocker"
INTPORT=80
EXTPORT=8086
docker rm -f "$NAME"
docker run -d \
	--env "SERVICE_${INTPORT}_CHECK_DOCKER=/usr/sbin/nginx -T" \
	--env "SERVICE_${INTPORT}_CHECK_TIMEOUT=10s" \
	--env "SERVICE_${INTPORT}_NAME=$NAME" \
	--hostname "$HOSTNAME" \
	--name "$NAME" \
	--publish "${EXTPORT}:${INTPORT}" \
	dummyservice
