FROM python:3.12-slim-bookworm AS base 
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

# General Setup and installtion
WORKDIR /app
RUN apt-get update -y
RUN apt-get install -y curl make gdb lldb wget ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https nuget iputils-ping

# Install caddy
RUN curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
RUN curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
RUN apt-get install caddy -y

# Install Mono
RUN gpg --homedir /tmp --no-default-keyring --keyring /usr/share/keyrings/mono-official-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
RUN echo "deb [signed-by=/usr/share/keyrings/mono-official-archive-keyring.gpg] https://download.mono-project.com/repo/ubuntu stable-focal main" | tee /etc/apt/sources.list.d/mono-official-stable.list
RUN apt-get update -y
RUN apt-get install -y mono-devel mono-complete msbuild msbuild-sdkresolver msbuild-libhostfxr

# Update nuget
RUN nuget update -self
RUN nuget sources add -Name nuget.org -Source https://api.nuget.org/v3/index.json

# start caddy
COPY Caddyfile /app/Caddyfile

WORKDIR /api
COPY templates /templates/
COPY start.sh /api/start.sh
COPY ./api/ /api
CMD ["/bin/bash", "/api/start.sh"]
