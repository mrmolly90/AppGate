FROM golang:1.23-alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /app
COPY . .
RUN go mod tidy
ENV CGO_ENABLED=0
RUN go build -o /app/server ./cmd/server
EXPOSE 8080
CMD ["/app/server"]