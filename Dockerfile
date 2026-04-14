FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl git make sudo \
        build-essential xorriso qemu-system-x86 \
        gnupg \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
 && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
 && curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
 && apt-get install -y --no-install-recommends gh nodejs \
 && npm install -g @anthropic-ai/claude-code \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN if id -u ubuntu >/dev/null 2>&1; then userdel --remove ubuntu; fi \
 && useradd --create-home --shell /bin/bash --uid 1000 agent \
 && echo "agent ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/agent

USER agent
ENV HOME=/home/agent \
    PATH=/home/agent/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Pre-install the pinned Rust toolchain so the first `cargo xtask build`
# inside the container doesn't pay the install cost. Staged in /tmp so the
# workdir stays empty for the clone at runtime.
COPY --chown=agent:agent rust-toolchain.toml /tmp/toolchain/rust-toolchain.toml
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain none --profile minimal \
 && cd /tmp/toolchain && rustup show active-toolchain && rustc --version && cargo --version \
 && rm -rf /tmp/toolchain

WORKDIR /home/agent/work

COPY --chown=root:root scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/auto-engineer"]
