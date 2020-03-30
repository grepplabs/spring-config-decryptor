FROM golang:1.14 as builder

ARG MAKE_TARGET="test build"

WORKDIR "/code"
ADD . "/code"
RUN make BINARY=spring-config-decryptor ${MAKE_TARGET}

FROM alpine:3.11
COPY --from=builder /code/spring-config-decryptor /spring-config-decryptor
ENTRYPOINT ["/spring-config-decryptor"]
