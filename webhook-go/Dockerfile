# Dockerfile para serviço webhook Go
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o webhook-server main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/webhook-server .
EXPOSE 8080
CMD ["./webhook-server"]
