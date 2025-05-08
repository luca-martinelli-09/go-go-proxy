FROM golang:tip-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -s" -o /app/proxy-server .

FROM alpine:3.21

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app/proxy-server /app/proxy-server

RUN chown appuser:appgroup /app && \
  chown appuser:appgroup /app/proxy-server && \
  chmod +x /app/proxy-server

USER appuser

CMD ["/app/proxy-server"]
