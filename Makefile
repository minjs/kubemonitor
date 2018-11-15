BINARY=agent
BUILD=`git rev-parse HEAD`
LDFLAGS=-ldflags "-w -s -X main.Build=${BUILD}"
CDIR = $(shell pwd)

build:
	GOPATH=${CDIR}/../../.. go build ${LDFLAGS} -o ${BINARY}
