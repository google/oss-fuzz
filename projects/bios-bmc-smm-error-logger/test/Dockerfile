FROM ubuntu:24.04

# Use non-interactive frontend for apt
ENV DEBIAN_FRONTEND=noninteractive

# Update apt and install systemd
# This will also pull in 'dbus' as a dependency
RUN apt-get update && apt-get install -y \
    systemd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY start.sh /usr/local/bin
RUN chmod +x /usr/local/bin/start.sh
ENTRYPOINT ["/bin/bash", "/usr/local/bin/start.sh"]