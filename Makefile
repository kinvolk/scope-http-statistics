.PHONY: run clean

IMAGE=weavescope-http-statistics-plugin
UPTODATE=.uptodate

run: $(UPTODATE)
	docker run --rm -it \
	  --privileged --net=host \
	  -v /lib/modules:/lib/modules \
	  -v /usr/src:/usr/src \
	  -v /sys/kernel/debug/:/sys/kernel/debug/ \
	  -v /var/run/scope/plugins:/var/run/scope/plugins \
	  --name $(IMAGE) \
	  $(IMAGE)

$(UPTODATE): Dockerfile http-statistics.py ebpf-programs/http-requests.c ebpf-programs/http-responses.c
	docker build -t $(IMAGE) .
	touch $@

clean:
	- rm -rf $(UPTODATE)
	- docker rmi $(IMAGE)
