# stage 1: build
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /polytokend ./cmd/polytokend

# stage 2: runtime
FROM alpine:latest
COPY --from=build /polytokend /polytokend
COPY config.yaml /config.yaml
EXPOSE 8080
CMD ["/polytokend"]
