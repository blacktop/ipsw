####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.18.3 as builder

COPY . /go/src/github.com/blacktop/ipsw
WORKDIR /go/src/github.com/blacktop/ipsw

RUN CGO_ENABLED=1 go build \
    -o /bin/ipsw \
    -ldflags "-X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=$(cat VERSION)" \
    -ldflags "-X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppBuildTime=$(date -u +%Y%m%d)" \
    ./cmd/ipsw

####################################################
# APFS-FUSE BUILDER
####################################################
FROM ubuntu:22.04

LABEL maintainer "https://github.com/blacktop"

ARG DEBIAN_FRONTEND=noninteractive

RUN buildDeps='libfuse3-dev bzip2 libbz2-dev libz-dev cmake build-essential git libattr1-dev' \
    && apt-get update \
    && apt-get install -y $buildDeps fuse3 unzip lzma tzdata \
    && echo "===> Installing apfs-fuse..." \
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

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
ENV IPSW_IN_DOCKER=1

COPY --from=builder /bin/ipsw /bin/ipsw

WORKDIR /data

ENTRYPOINT [ "/bin/ipsw" ]
CMD [ "--help" ]