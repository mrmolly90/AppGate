FROM rust:1.98-alpine
WORKDIR /app
COPY . .
RUN apk add --no-cache musl-dev
RUN cargo build --release
EXPOSE 8443
CMD ["./target/release/appgate-gateway"]