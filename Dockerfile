FROM debian:bookworm-slim
WORKDIR /work
COPY . .
# ax doctor bind-mounts the host ax binary at /usr/local/bin/ax
CMD ["ax", "check"]
