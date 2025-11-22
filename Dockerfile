# Multi-stage build for minimal Go binary image
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ghost_route main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/ghost_route .
COPY --from=builder /app/static ./static
EXPOSE 8080
ENTRYPOINT ["/app/ghost_route"]