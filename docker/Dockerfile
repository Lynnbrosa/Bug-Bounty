# syntax=docker/dockerfile:1.7

# -----------------------------------------------------------------------------
# Stage 1: build the Go toolchain binaries used by bounty-agent
# -----------------------------------------------------------------------------
FROM golang:1.22-bookworm AS gobuild

ENV GOPATH=/go \
    PATH=/go/bin:$PATH \
    CGO_ENABLED=0

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/tomnomnom/waybackurls@latest


# -----------------------------------------------------------------------------
# Stage 2: install Python deps and build the wheel
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS pybuild

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip build && \
    python -m build --wheel --outdir /wheels


# -----------------------------------------------------------------------------
# Stage 3: runtime image
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/usr/local/bin:$PATH

# Install only the binaries we need from the gobuild stage.
COPY --from=gobuild /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=gobuild /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=gobuild /go/bin/httpx /usr/local/bin/httpx
COPY --from=gobuild /go/bin/dnsx /usr/local/bin/dnsx
COPY --from=gobuild /go/bin/katana /usr/local/bin/katana
COPY --from=gobuild /go/bin/naabu /usr/local/bin/naabu
COPY --from=gobuild /go/bin/waybackurls /usr/local/bin/waybackurls

COPY --from=pybuild /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Ship the default templates and config so the image is usable out of the box.
COPY config /etc/bounty-agent/config
COPY nuclei-templates /etc/bounty-agent/nuclei-templates

# Run as an unprivileged user.
RUN useradd --create-home --shell /usr/sbin/nologin bounty
USER bounty
WORKDIR /home/bounty

ENV BOUNTY_AGENT_CONFIG=/etc/bounty-agent/config/default.yaml

ENTRYPOINT ["bounty-agent"]
CMD ["--help"]
