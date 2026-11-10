IMAGE := ngx-blocklist-test

.PHONY: build test shell clean

build:
	docker build -t $(IMAGE) .

test: build
	docker run --rm $(IMAGE)

shell: build
	docker run --rm -it $(IMAGE) bash

clean:
	-docker rmi $(IMAGE)
