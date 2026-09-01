FROM rust:1.75-alpine AS builder

RUN apk add --no-crate-pkg-config musl-dev gcc

WORKDIR /app
COPY . .

RUN cargo build --release -p privacy-relay

FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/target/release/privacy-relay /app/privacy-relay

EXPOSE 8080

ENV RUST_LOG=off

ENTRYPOINT ["/app/privacy-relay"]
