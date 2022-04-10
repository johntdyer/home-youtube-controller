# Replace demo with your desired executable name
appname := youtube

sources := $(wildcard *.go)

build = GOOS=$(1) GOARCH=$(2) go build -o build/$(appname)$(3)
tar = cd build && tar -cvzf $(1)_$(2).tar.gz $(appname)$(3) && rm $(appname)$(3)
zip = cd build && zip $(1)_$(2).zip $(appname)$(3) && rm $(appname)$(3)

.PHONY: all darwin linux clean

all: darwin linux

clean:
		rm -rf build/

##### LINUX BUILDS #####
linux: build/linux_arm.tar.gz build/linux_arm64.tar.gz build/linux_amd64.tar.gz



build/linux_amd64.tar.gz: $(sources)
		$(call build,linux,amd64,)
		$(call tar,linux,amd64)

build/linux_arm.tar.gz: $(sources)
		$(call build,linux,arm,)
		$(call tar,linux,arm)

build/linux_arm64.tar.gz: $(sources)
		$(call build,linux,arm64,)
		$(call tar,linux,arm64)

##### DARWIN (MAC) BUILDS #####
darwin: build/darwin_amd64.tar.gz

build/darwin_amd64.tar.gz: $(sources)
		$(call build,darwin,amd64,)
		$(call tar,darwin,amd64)
