# syntax=docker.io/docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv

##################################################
## "build" stage
##################################################

FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/golang:1.26.2-trixie@sha256:c0074c718b473f3827043f86532c4c0ff537e3fe7a81b8219b0d1ccfcc2c9a09 AS build

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG SOURCE_DATE_EPOCH

WORKDIR /src/
COPY ./go.mod ./go.sum ./
RUN go mod download
COPY ./ ./
RUN make test
RUN make build \
		GOOS="${TARGETOS-}" \
		GOARCH="${TARGETARCH-}" \
		GOARM="$([ "${TARGETARCH-}" != 'arm' ] || printf '%s' "${TARGETVARIANT#v}")"
RUN test -z "$(readelf -x .interp ./dist/cardea-* 2>/dev/null)"

WORKDIR /rootfs/
RUN install -DTm 0555 /src/dist/cardea-* ./cardea
RUN mkdir -m 1777 ./run/ ./tmp/ ./data/ ./data/recordings/

##################################################
## "main" stage
##################################################

FROM scratch AS main

COPY --from=build /rootfs/ /

ENV CARDEA_LISTEN=:2222
ENV CARDEA_HEALTH_LISTEN=:9222
ENV CARDEA_PRIVATE_KEY_FILE=/data/private_key
ENV CARDEA_TPM_KEY_FILE=/data/tpm_key.blob
ENV CARDEA_AUTHORIZED_KEYS_FILE=/data/authorized_keys
ENV CARDEA_KNOWN_HOSTS_FILE=/data/known_hosts
ENV CARDEA_RECORDINGS_DIR=/data/recordings/

USER 10022:10022
ENTRYPOINT ["/cardea"]
