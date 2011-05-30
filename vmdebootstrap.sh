#!/bin/bash

set -x
set -e

if ! [ -r /etc/grml_cd ] ; then
  echo "Not running inside Grml, exiting to avoid damage." >&2
  exit 1
fi

# FIXME - integrate in vmdebootstrap
wget grml.org/sipwise/bootgrub.mksh

# FIXME - don't depend on it
if ! [ -d /mnt/sda1/lost+found ] ; then
  mount /dev/sda1 /mnt/sda1
fi

# FIXME - integrate in deployment ISO
apt-get update ; apt-get -y install kpartx qemu-utils mksh

IMAGE=/mnt/sda1/qemu.img
TMPDIR=$(mktemp -d) || exit 1

qemu-img create -f raw "${IMAGE}" 3G
echo 4 66 | mksh bootgrub.mksh -A | dd of="$IMAGE" conv=notrunc
dd if=/dev/zero bs=1 conv=notrunc count=64 seek=446 of="$IMAGE"
parted -s "${IMAGE}" 'mkpart primary ext3 2M -1'

DEVINFO=$(kpartx -av $IMAGE) # 'add map loop1p1 (253:0): 0 6289408 linear /dev/loop1 2048'
if [ -z "$DEVINFO" ] ; then
  echo  Error setting up loopback device >&2
  exit 1
fi

LOOP=$(echo ${DEVINFO} | sed 's/.* linear //; s/ [[:digit:]]*//') # '/dev/loop1'
BLOCKDEV=$(echo "${DEVINFO}" | sed -e 's/.* (\(.*:.*\)).*/\1/')   # '253:0'
LOOP_PART="$(echo ${DEVINFO##add map } | sed 's/ .*//')" # '/dev/loop1p1'
TARGET="/dev/mapper/$LOOP_PART" # '/dev/mapper/loop1p1'

echo "Debug:
DEVINFO=$DEVINFO
LOOP=$LOOP
BLOCKDEV=$BLOCKDEV
LOOP_PART=$LOOP_PART
TARGET=$TARGET
"

blockdev --rereadpt $LOOP

echo FSCK=no >> /etc/debootstrap/config
echo y | grml-debootstrap --hostname vmbuilder --mirror http://debian.inode.at/debian/ -r squeeze -t "$TARGET" --password foobar

kpartx -d $IMAGE
LOOPDEV=$(losetup -f)
losetup $LOOPDEV ${IMAGE}
reread_partition_table $LOOP
mount /dev/$LOOP_PART $TMPDIR

mkdir -p "$TMPDIR/boot/grub"
cp "$TMPDIR"/usr/lib/grub/i386-pc/* "$TMPDIR/boot/grub/"
grml-chroot "$TMPDIR" grub-mkimage -O i386-pc -p "(hd0,msdos1)/boot/grub" -o /tmp/core.img biosdisk part_msdos ext2
dd if="$TMPDIR/tmp/core.img" of="$IMAGE" conv=notrunc seek=4

grml-chroot $TMPDIR update-grub

sed -i "s;set root=.*;set root='(hd0,msdos1)';" $TMPDIR/boot/grub/grub.cfg
# sed 's/insmod ext2/insmod ext2\n        insmod part_msdos/'  $TMPDIR/boot/grub/grub.cfg

cat $TMPDIR/boot/grub/grub.cfg > /tmp/grub.cfg

umount $TMPDIR
rmdir $TMPDIR
losetup -d "$LOOPDEV"

echo 'done :)'

# EOF
