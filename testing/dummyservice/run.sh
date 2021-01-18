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
