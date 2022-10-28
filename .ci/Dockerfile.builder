FROM alpine:latest

RUN apk add libsodium-dev libsodium-static binutils-gold zlib-static zlib-dev curl gcc gmp-dev libc-dev libffi-dev make musl-dev ncurses-dev perl tar xz
ENV BOOTSTRAP_HASKELL_NONINTERACTIVE=1
ENV BOOTSTRAP_HASKELL_INSTALL_NO_STACK=1
ENV BOOTSTRAP_HASKELL_INSTALL_HLS=0
ENV BOOTSTRAP_HASKELL_GHC_VERSION="9.0.2"
RUN curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
ADD . /build
WORKDIR ./build
RUN mv .ci/static.cabal.project cabal.project
RUN source /root/.ghcup/env cabal update && cabal build --dependencies-only powerdns-gerd
#RUN source /root/.ghcup/env && ghcup install ghc 9.0.2
#RUN source /root/.ghcup/env && ghcup set ghc 9.0.2 && cabal update && cabal build --dependencies-only powerdns-gerd
