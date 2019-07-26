FROM ubuntu:19.04

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

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]