FROM python:3.12-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Base packages
RUN apt-get update && \
    apt-get install -y \
        curl \
        wget \
        gnupg \
        ca-certificates \
        apt-transport-https \
        debian-keyring \
        debian-archive-keyring \
        make \
        gdb \
        lldb \
        nuget \
        iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# -------------------------
# Caddy Repository
# -------------------------
RUN curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

RUN curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    > /etc/apt/sources.list.d/caddy-stable.list

# -------------------------
# Mono Repository
# -------------------------
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 \
    --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF

RUN echo "deb https://download.mono-project.com/repo/ubuntu stable-bionic main" \
    > /etc/apt/sources.list.d/mono-official-stable.list

# Install packages
RUN apt-get update && \
    apt-get install -y \
        caddy \
        mono-devel \
        mono-complete \
        msbuild \
        msbuild-sdkresolver \
        msbuild-libhostfxr && \
    rm -rf /var/lib/apt/lists/*

# Update NuGet
RUN nuget update -self
RUN nuget sources Add \
    -Name nuget.org \
    -Source https://api.nuget.org/v3/index.json

COPY Caddyfile /app/Caddyfile

COPY templates /templates

WORKDIR /api

COPY api/ .
COPY start.sh .

RUN chmod +x start.sh

CMD ["/bin/bash", "/api/start.sh"]
