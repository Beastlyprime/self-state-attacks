FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      autoconf automake autoconf-archive bison build-essential flex \
      libgcrypt20-dev libpcre2-dev zlib1g-dev pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY source /src/aide
WORKDIR /src/aide
RUN GIT_VERSION=v0.19.3 ./autogen.sh \
 && ./configure --prefix=/usr --sysconfdir=/etc \
 && make -j2 \
 && make install

ENTRYPOINT ["/usr/bin/aide"]
