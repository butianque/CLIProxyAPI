FROM golang:1.26-bookworm AS builder

WORKDIR /app

# Module proxy is a build-time knob: the default works anywhere, and a mirror can
# be passed with --build-arg when the public proxy is slow or blocked.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# Keep the compiler inside a small Docker VM: four parallel package builds plus
# CGO can exceed a 4 GB VM and then the build barely progresses because it is
# thrashing. Two is the sweet spot here and costs little on a larger machine.
ENV GOMAXPROCS=2
ENV GOFLAGS=-p=2

# The golang image is built on buildpack-deps, so gcc, g++, make and git are
# already present; installing build-essential again only costs a slow apt round
# trip. CGO is still required: the plugin host dlopens shared objects.

COPY go.mod go.sum ./

# Cache mounts keep the module and build caches between image builds. Without
# them every blue-green deploy recompiles the whole dependency tree from scratch.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build -buildvcs=false -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" -o ./CLIProxyAPI ./cmd/server/

FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends tzdata ca-certificates && rm -rf /var/lib/apt/lists/*

RUN mkdir /CLIProxyAPI

COPY --from=builder ./app/CLIProxyAPI /CLIProxyAPI/CLIProxyAPI

COPY config.example.yaml /CLIProxyAPI/config.example.yaml

WORKDIR /CLIProxyAPI

EXPOSE 8317

ENV TZ=Asia/Shanghai

RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime && echo "${TZ}" > /etc/timezone

CMD ["./CLIProxyAPI"]
