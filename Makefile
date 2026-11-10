# Local build & test (no docker).
#
# Prerequisites on the host:
#   - nginx binary installed (for its binary version + Test::Nginx to launch)
#   - gcc, make, curl, tar
#   - Test::Nginx::Socket and its Perl deps (e.g. cpanm Test::Nginx::Socket)
#   - libssl-dev, libpcre2-dev (or libpcre3-dev), zlib1g-dev for building
#
# make build  → download matching nginx source, build the .so into build/
# make test   → build if needed, then prove -v t/ against the built module
# make clean  → remove build/
#
# Docker wrappers (still available):
#   make docker-build / docker-test / docker-shell

NGINX_VERSION ?= $(shell nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')
BUILD_DIR     := build
NGINX_SRC     := $(BUILD_DIR)/nginx-$(NGINX_VERSION)
MODULE_SO     := $(NGINX_SRC)/objs/ngx_http_blocklist_module.so
MODULE_SRCS   := $(wildcard src/*.c src/*.h) config

IMAGE := ngx-blocklist-test

.PHONY: build test shell clean docker-build docker-test docker-shell docker-clean

build: $(MODULE_SO)

$(NGINX_SRC)/auto/configure: | $(BUILD_DIR)
	curl -fsSL "https://nginx.org/download/nginx-$(NGINX_VERSION).tar.gz" \
	  | tar -xz -C $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(NGINX_SRC)/Makefile: $(NGINX_SRC)/auto/configure $(MODULE_SRCS)
	cd $(NGINX_SRC) && ./configure \
	    --with-compat \
	    --with-http_realip_module \
	    --add-dynamic-module=$(CURDIR)

$(MODULE_SO): $(NGINX_SRC)/Makefile $(MODULE_SRCS)
	$(MAKE) -C $(NGINX_SRC) modules

test: $(MODULE_SO)
	TEST_NGINX_LOAD_MODULES=$(CURDIR)/$(MODULE_SO) prove -v t/

shell: ## no-op in local mode; use `docker-shell` if you want the containerised shell
	@echo "shell target is docker-only; use: make docker-shell"

clean:
	rm -rf $(BUILD_DIR)

# -----------------------------------------------------------------------------
# Docker wrappers (unchanged behaviour).
docker-build:
	docker build -t $(IMAGE) .

docker-test: docker-build
	docker run --rm $(IMAGE)

docker-shell: docker-build
	docker run --rm -it $(IMAGE) bash

docker-clean:
	-docker rmi $(IMAGE)
