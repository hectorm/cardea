# syntax=docker.io/docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv

##################################################
## "build" stage
##################################################

FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/golang:1.26.1-trixie@sha256:96b28783b99bcd265fbfe0b36a3ac6462416ce6bf1feac85d4c4ff533cbaa473 AS build

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
