FROM python@sha256:de52085267e18aba7083768f283765fcd04f753aba32cc85e62a39c77670cf4b

RUN printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20200414T000000Z buster main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20200414T000000Z buster/updates main' \
      > /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      make python-numpy python-scipy python-sklearn python-tqdm \
 && find /usr/lib/python2.7/dist-packages -type f -name "*.aarch64-linux-gnu.so" \
      -exec sh -c 'ln -s "$1" "${1%.aarch64-linux-gnu.so}.so"' _ {} \; \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip install --no-cache-dir --no-deps xxhash==1.4.3 sklearn==0.0

ENV PYTHONPATH=/usr/lib/python2.7/dist-packages
