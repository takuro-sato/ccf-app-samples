# Based on https://hub.docker.com/_/golang/

# To run this:
#   docker build -t attestation-container .
#   docker run -it --rm -p 50051:50051 attestation-container

FROM golang:1.19

WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go build -v -o /usr/local/bin/app .
RUN git clone https://github.com/microsoft/confidential-sidecar-containers.git \
    && cd confidential-sidecar-containers \
    && cd tools/get-snp-report && make && cd ../.. \
    && cp tools/get-snp-report/bin/get-snp-report /bin \
    && cp tools/get-snp-report/bin/get-fake-snp-report /bin

CMD ["app"]
