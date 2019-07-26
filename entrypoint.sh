#!/bin/bash

set -ex

unzip -j /data/*.ipsw '*.dmg' -d /tmp

DMG=$(find /tmp -type f -printf '%s %p\n' | sort -nr | head -n1 | awk '{print $2;}')

echo " > Mounting $DMG at /app..."
apfs-fuse $DMG /app

echo " > Copying dyld_shared_cache..."
cp /app/root/System/Library/Caches/com.apple.dyld/dyld_shared_cache_* /data

echo " > Unmounting /app..."
umount /app