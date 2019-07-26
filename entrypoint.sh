#!/bin/bash

set -ex

unzip -j /data/*.ipsw '*.dmg' -d /tmp

DMG=$(find /tmp -type f -printf '%s %p\n' | sort -nr | head -n1 | awk '{print $2;}')

apfs-fuse $DMG /app

cp /app/root/System/Library/Caches/com.apple.dyld/dyld_shared_cache_* /data