FROM alpine:latest

ENV BOOTSTRAP_HASKELL_NONINTERACTIVE=1
RUN apk add libsodium-dev libsodium-static binutils-gold zlib-static zlib-dev curl gcc gmp-dev libc-dev libffi-dev make musl-dev ncurses-dev perl tar xz
RUN curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
RUN source /root/.ghcup/env
