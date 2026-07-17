# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Сначала копируем файлы модулей отдельно,
# чтобы Docker мог кэшировать загрузку зависимостей.
COPY go.mod ./

RUN go mod download

COPY . .

# Собираем статический Linux-бинарник.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/csr-inspector \
    ./cmd/server


FROM alpine:3.22 AS runtime

RUN apk add --no-cache \
        ca-certificates \
        tzdata \
    && addgroup \
        -S \
        csr-inspector \
    && adduser \
        -S \
        -G csr-inspector \
        -H \
        -s /sbin/nologin \
        csr-inspector

WORKDIR /app

COPY --from=build \
    /out/csr-inspector \
    /app/csr-inspector

USER csr-inspector:csr-inspector

EXPOSE 8080

ENTRYPOINT ["/app/csr-inspector"]