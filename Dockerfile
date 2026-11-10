# Build and test image for ngx_http_blocklist_module.
#
# The module is built as a dynamic .so against upstream nginx source matching
# Debian's installed nginx binary. `--with-compat` lets the .so load into the
# system nginx without a full nginx rebuild.
#
# Build:  docker build -t ngx-blocklist-test .
# Test :  docker run --rm ngx-blocklist-test
# Shell:  docker run --rm -it ngx-blocklist-test bash
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      libpcre2-dev \
      libpcre3-dev \
      libssl-dev \
      zlib1g-dev \
      perl \
      libtest-nginx-perl \
      libio-socket-ssl-perl \
      curl \
      ca-certificates \
      nginx \
 && rm -rf /var/lib/apt/lists/*

# Download nginx source whose version matches the installed binary. Modules
# built with --with-compat against matching major.minor load into the system
# nginx cleanly.
WORKDIR /opt/nginx-src
RUN set -eu \
 && NGINX_VERSION=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p') \
 && echo "Building against nginx ${NGINX_VERSION}" \
 && curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
    | tar -xz --strip-components=1

COPY config /src/config
COPY src/   /src/src/

RUN ./configure \
      --with-compat \
      --with-http_realip_module \
      --add-dynamic-module=/src \
 && make modules -j"$(nproc)" \
 && mkdir -p /usr/lib/nginx/modules \
 && cp objs/ngx_http_blocklist_module.so /usr/lib/nginx/modules/

WORKDIR /src
COPY t/ /src/t/

# Test::Nginx injects `load_module <path>;` when TEST_NGINX_LOAD_MODULES is set.
ENV TEST_NGINX_LOAD_MODULES=/usr/lib/nginx/modules/ngx_http_blocklist_module.so

CMD ["prove", "-v", "t/"]
