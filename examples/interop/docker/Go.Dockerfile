FROM golang:1.25-bookworm AS builder

WORKDIR /suite
COPY examples/interop/go/client.go examples/interop/go/recursive.go ./

RUN CGO_ENABLED=0 go build -o /client client.go \
    && CGO_ENABLED=0 go build -o /recursive-client recursive.go

FROM debian:bookworm-slim

COPY --from=builder /client /recursive-client /usr/local/bin/

CMD ["client"]
