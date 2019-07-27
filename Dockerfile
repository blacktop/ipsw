####################################################
# GOLANG BUILDER
####################################################
FROM golang:1 as go_builder

COPY . /go/src/github.com/blacktop/ipsw
WORKDIR /go/src/github.com/blacktop/ipsw

RUN go build -o /bin/ipsw -ldflags "-s -w -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=$(cat VERSION) -X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppBuildTime==$(date -u +%Y%m%d)" ./cmd/ipsw

####################################################
# APFS-FUSE BUILDER
####################################################
FROM ubuntu:19.04

LABEL maintainer "https://github.com/blacktop"

RUN buildDeps='libfuse3-dev bzip2 libbz2-dev libz-dev cmake build-essential git libattr1-dev' \
    && apt-get update \
    && apt-get install -y $buildDeps fuse3 unzip \
    && cd /tmp \
    && git clone https://github.com/sgan81/apfs-fuse.git \
    && cd apfs-fuse \
    && git submodule init \
    && git submodule update \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make install \
    && echo "===> Clean up unnecessary files..." \
    && apt-get purge -y --auto-remove $buildDeps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=go_builder /bin/ipsw /bin/ipsw

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]