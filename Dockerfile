FROM golang:alpine AS builder
ENV CGO_ENABLED=1
RUN apk add --no-cache gcc musl-dev
WORKDIR /code
COPY . .
RUN go build -o forum ./cmd/main.go

FROM alpine:latest
WORKDIR /code
COPY --from=builder /code .
CMD ["./forum"]
