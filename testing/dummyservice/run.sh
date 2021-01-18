#!/bin/bash
docker build . -t dummyservice

function runservice() {
	INTPORT=80
	EXTPORT=$1
	NAME="dummyservice${EXTPORT}"
	docker rm -f "$NAME"
	docker run -d \
		--hostname "$HOSTNAME" \
		--env "SERVICE_NAME=dummyservicenoportfromenv" \
		--env "SERVICE_TAGS=noporttag" \
		--label "SERVICE_NAME=dummyservicenoportfromlabel" \
		--label "SERVICE_CHECK_INTERVAL=25s" \
		--env "SERVICE_${INTPORT}_CHECK_TCP=true" \
		--env "SERVICE_${INTPORT}_CHECK_TIMEOUT=10s" \
		--env "SERVICE_${INTPORT}_NAME=dummyservice" \
		--label "SERVICE_180_NAME=dummyservice180" \
		--label "SERVICE_${INTPORT}_TAGS=prod,dummytag" \
		--name "$NAME" \
		--publish "${EXTPORT}:${INTPORT}" \
		--publish "2${EXTPORT}:${INTPORT}" \
		--publish "1${EXTPORT}:1${INTPORT}/udp" \
		dummyservice
}

runservice 8081
runservice 8082
