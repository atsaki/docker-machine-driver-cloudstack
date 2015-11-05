default: build

bin/docker-machine-driver-cloudstack:
	go build -i -o ./bin/docker-machine-driver-cloudstack ./bin

clean:
	$(RM) bin/docker-machine-driver-cloudstack

build: clean bin/docker-machine-driver-cloudstack

install: bin/docker-machine-driver-cloudstack
	cp -f ./bin/docker-machine-driver-cloudstack $(GOPATH)/bin

.PHONY: clean build install
