FROM golang:1.23-alpine
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o /app/server ./cmd/server
EXPOSE 8080
CMD ["/app/server"]