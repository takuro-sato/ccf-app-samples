# Based on https://hub.docker.com/_/golang/

# To run this:
#   docker build -t attestation-container .
#   docker run -it -rm attestation-container 

FROM golang:1.19

WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change

# go.sum is used after adding dependencies
# COPY go.mod go.sum ./
COPY go.mod ./
RUN go mod download && go mod verify

COPY . .
RUN go build -v -o /usr/local/bin/app ./...

CMD ["app"]
