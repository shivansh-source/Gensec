# syntax=docker/dockerfile:1
# Pinned to a Go patch >= go.mod's `go 1.24.5` requirement — golang:1.24-alpine3.20
# resolves to 1.24.3 and fails the build, so this needs to stay >= 1.24.5.
FROM golang:1.24.7-alpine3.21 AS builder
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux go build -o gensec ./cmd/gensec

FROM alpine:3.21

LABEL org.opencontainers.image.title="gensec" \
      org.opencontainers.image.description="Self-healing DevSecOps agent: scans, triages, and opens PRs fixing vulnerabilities." \
      org.opencontainers.image.source="https://github.com/shivansh-source/gensec"

RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    curl \
    bash \
    gcc \
    musl-dev \
    ca-certificates

# Let pip install into system environment (PEP 668)
ENV PIP_BREAK_SYSTEM_PACKAGES=1

# Semgrep from pip
RUN pip3 install --no-cache-dir semgrep

# Gitleaks from GitHub release (Go binary)
ENV GITLEAKS_VERSION=8.18.4
RUN curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
 && chmod +x /usr/local/bin/gitleaks

# Trivy install script, pinned to a known-good release rather than @main
ENV TRIVY_VERSION=0.74.0
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"

COPY --from=builder /build/gensec /usr/local/bin/gensec
RUN chmod +x /usr/local/bin/gensec

WORKDIR /scan

ENV USER_PLAN="pro"

ENTRYPOINT ["gensec"]
CMD ["scan"]
