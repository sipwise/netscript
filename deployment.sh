#!/bin/bash
# Purpose: automatically install Debian squeeze + ngcp-installer

# Ideas:
# * rename kantan host into spce (bootoption in ISO)
# * support configuration via wget-able config file

set -e
# set -x

# better safe than sorry
export LC_ALL=C
export LANG=C

# defaults
TARGET=/mnt
PRO_EDITION=false
CE_EDITION=false
NGCP_INSTALLER=false
INTERACTIVE=false

### helper functions {{{
CMD_LINE=$(cat /proc/cmdline)
stringInString() {
  local to_test_="$1"   # matching pattern
  local source_="$2"    # string to search in
  case "$source_" in *$to_test_*) return 0;; esac
  return 1
}

checkBootParam() {
  stringInString " $1" "$CMD_LINE"
  return "$?"
}

getBootParam() {
  local param_to_search="$1"
  local result=''

  stringInString " $param_to_search=" "$CMD_LINE" || return 1
  result="${CMD_LINE##*$param_to_search=}"
  result="${result%%[   ]*}"
  echo "$result"
  return 0
}

# fscking "=" missing in keybindings of Promox's OpenVNC console
getProxmoxBootParam() {
  local param_to_search="$1"
  local result=''

  stringInString " $param_to_search/" "$CMD_LINE" || return 1
  result="${CMD_LINE##*$param_to_search/}"
  result="${result%%[   ]*}"
  echo "$result"
  return 0
}
### }}}

# provide method to boot live system without running installer
if checkBootParam noinstall ; then
  echo "Exiting as requested via bootoption noinstall."
  exit 0
fi

## detect environment {{{
if dmidecode| grep -q 'Location In Chassis'; then
 CHASSIS="Running in blade chassis $(dmidecode| awk '/Location In Chassis/ {print $4}')"
 PRO_EDITION=true
fi

if $PRO_EDITION ; then
  ROLE=sp1

  if checkBootParam ngcpsp2 ; then
    ROLE=sp2
  fi
fi

if checkBootParam nongcp ; then
  echo "Will not execute ngcp-installer as requested via bootoption nongcp."
  NGCP_INSTALLER=false
fi

if checkBootParam ngcpinst ; then
  NGCP_INSTALLER=true
fi

# configure static network in installed system?
# WFM code right now, depends on 192.168.51.X!
if checkBootParam ngcpip ; then
  DEVIP="$(getBootParam ngcpip)" || true
  if [ -z "$DEVIP" ] ; then
    DEVIP="$(getProxmoxBootParam ngcpip)"
  fi
fi

if checkBootParam ngcphostname ; then
  TARGET_HOSTNAME="$(getBootParam ngcphostname)" || true
  if [ -z "$TARGET_HOSTNAME" ] ; then
    TARGET_HOSTNAME="$(getProxmoxBootParam ngcphostname)"
  fi
else
  if $PRO_EDITION ; then
    TARGET_HOSTNAME="$ROLE"
  else
    TARGET_HOSTNAME="spce"
  fi
fi
## }}}

## interactive mode {{{
# support command line options, overriding autodetected defaults
INTERACTIVE=true

if [ -n "$NETSCRIPT" ] ; then
  echo "Automatic deployment via bootoption netscript detected."
  INTERACTIVE=false
fi

usage() {
  echo "$0 - automatically deploy Debian squeeze and (optionally) ngcp ce/pro.

  ngcppro          - install Pro Edition
  ngcpsp1          - install first node (Pro Edition only)
  ngcpsp2          - install second node (Pro Edition only)
  ngcpce           - install CE Edition
  nongcp           - do not install NGCP but install plain Debian only
  noinstall        - do not install neither Debian nor NGCP
  ngcpinst         - force usage of NGCP installer
  ngcpip=...       - set IP address of installed system (defaults to dhcp) (WIP)
  ngcphostname=... - set hostname of installed system (defaults to ngcp/sp[1,2])
  ngcpprofile=...  - download additional configuration profile (WIP)

The command line options correspond with the available bootoptions.
Command line overrides any present bootoption.

"
}

for param in $* ; do
  case $param in
    *-h*|*--help*|*help*) usage ; exit 0;;
    *ngcpip=*) DEVIP=$(echo $param | sed 's/ngcpip=//');;
    *ngcpsp1*) ROLE=sp1 ; PRO_EDITION=true; CE_EDITION=false ;;
    *ngcpsp2*) ROLE=sp2 ; PRO_EDITION=true; CE_EDITION=false ;;
    *ngcppro*) PRO_EDITION=true; CE_EDITION=false ; NGCP_INSTALLER=true ;;
    *ngcpce*) PRO_EDITION=false; CE_EDITION=true ; TARGET_HOSTNAME=spce ; ROLE='' ; NGCP_INSTALLER=true ;;
    *nongcp*) NGCP_INSTALLER=false;;
    *nodebian*) DEBIAN_INSTALLER=false;; # TODO
    *noinstall*) NGCP_INSTALLER=false; DEBIAN_INSTALLER=false;;
    *ngcpinst*) NGCP_INSTALLER=true;;
    *ngcphostname=*) TARGET_HOSTNAME=$(echo $param | sed 's/ngcphostname=//');;
    *ngcpprofile=*) PROFILE=$(echo $param | sed 's/ngcpprofile=//');;
  esac
  shift
done

echo "Deployment Settings:

  Install ngcp:    $NGCP_INSTALLER
  IP of host:      $DEVIP
  Host Role:       $ROLE
  Hostname:        $TARGET_HOSTNAME
  Profile:         $PROFILE
  Installer - pro: $PRO_EDITION
  Installer - ce:  $CE_EDITION

  $CHASSIS
"

if $INTERACTIVE ; then
  echo "Settings OK? y/N"
  read a
  if [[ "$a" != "y" ]] ; then
    echo "Exiting as requested."
    exit 0
  fi
  unset a
fi
## }}}

if $PRO_EDITION ; then
  if ifconfig usb0 &>/dev/null ; then
    ifconfig usb0 169.254.1.102 netmask 255.255.0.0
  fi
fi

# if checkBootParam ngcpfirmware ; then
# not enabled for now
#  # uefi firmware upgrade
#  if hwinfo --bios  | grep -q 'UEFI Primary Version -\[P9' ; then
#    ./ibm_fw_uefi_p9e149a_linux_32-64.bin -s
#  fi
#
#  # raid controller upgrade
#  if hwinfo --disk | grep -q 'ServeRAID-MR10ie' ; then
#   ./ibm_fw_sraidmr_10ie-11.0.1-0040.01_linux_32-64.bin -s
#  fi
# fi

# wget http://delivery04.dhe.ibm.com/sar/CMA/XSA/02gcs/1/ibm_utl_asu_asut72l_linux_x86-64.tgz
# unp ibm_utl_asu_asut72l_linux_x86-64.tgz
# ./asu64 set BootOrder.BootOrder 'Hard Disk 0=USB Storage=CD/DVD Rom'

# run in according environment only
if [[ $(imvirt) == "Physical" ]] ; then
  # FIXME: hardcoded for now, needs better check to support !ServeRAID-MR10ie as well
  if ! grep -q 'ServeRAID-MR10ie' /sys/block/sda/device/model ; then
    echo "Error: /dev/sda does not look like a ServeRAID disk." >&2
    echo "Exiting to avoid possible data damage." >&2
    exit 1
  fi
else
  # make sure it runs only within qemu/kvm
  if ! grep -q 'QEMU HARDDISK' /sys/block/sda/device/model ; then
    echo "Error: /dev/sda does not look like a virtual disk." >&2
    echo "Exiting to avoid possible data damage." >&2
    exit 1
  fi
fi

# measure time of installation procedure - everyone loves stats!
start_seconds=$(cut -d . -f 1 /proc/uptime)

# when using ip=....:$HOSTANEM:eth0:off file /etc/hosts doesn't contain the
# hostname by default, avoid warning/error messages in the host system

if [ -x /usr/bin/ifdata ] ; then
  IP="$(ifdata -pa eth0)"
else
  IP='192.168.51.123'
fi

# TODO - improve :)
if checkBootParam ngcpprofile ; then
  PROFILE="$(getBootParam ngcpprofile)" || true
  if [ -z "$PROFILE" ] ; then
    PROFILE="$(getProxmoxBootParam ngcpprofile)"
  fi

  wget http://deb.sipwise.com/kantan/$PROFILE
  . $PROFILE
fi

if [ -n "$HOSTNAME" ] ; then
  cat > /etc/hosts << EOF
127.0.0.1       grml    localhost
::1     ip6-localhost ip6-loopback grml
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

127.0.0.1 $HOSTNAME
$IP $HOSTNAME
EOF
fi

# remote login ftw
/etc/init.d/ssh start >/dev/null &
echo "root:grml2011" | chpasswd

# partition disk
# do not depend on static value (like 33554432 for 16GB)
if [[ $(imvirt) == "Physical" ]] || $PRO_EDITION ; then
  # remove existing partitioning
  #  dd if=/dev/zero of=/dev/sda bs=512 count=1
  #  partprobe /dev/sda ; sync

  parted -s /dev/sda mktable msdos
  # hw-raid with 1 rootfs and 1 swap partition
  parted -s /dev/sda 'mkpart primary ext4 2048s 95%'
  parted -s /dev/sda 'mkpart primary linux-swap 95% -1'

else
  # just one disk, assuming VM installation without swap partition
  disksize=$(cat /sys/block/sda/size)
  disksize=$(echo $(($disksize-2048))) # proper alignment for grub and performance

  sfdisk /dev/sda <<ENDDISK
# partition table of /dev/sda
unit: sectors

/dev/sda1 : start=     2048, size= ${disksize}, Id=83
/dev/sda2 : start=        0, size=        0, Id= 0
/dev/sda3 : start=        0, size=        0, Id= 0
/dev/sda4 : start=        0, size=        0, Id= 0
ENDDISK

fi

sync

# otherwise e2fsck fails with "need terminal for interactive repairs"
echo FSCK=no >>/etc/debootstrap/config

# package selection
cat > /etc/debootstrap/packages << EOF
# addons: packages which d-i installs but debootstrap doesn't
eject
grub-pc
locales
pciutils
usbutils
ucf

# required for dkms
linux-headers-2.6-amd64

# packages d-i installs but we ignore/skip:
#acpi
#acpid
#acpi-support-base
#discover
#gettext-base
#installation-report
#kbd
#laptop-detect
#os-prober
EOF

if $PRO_EDITION ; then
  cat >> /etc/debootstrap/packages << EOF
# required for "Broadcom NetXtreme II BCM5709S Gigabit Ethernet"
firmware-bnx2
firmware-bnx2x

# support 32bit binaries, e.g. for firmware upgrades
ia32-libs
EOF
fi

# install Debian squeeze
yes | grml-debootstrap --grub /dev/sda --hostname "${TARGET_HOSTNAME}" --mirror http://debian.inode.at/debian/ -r squeeze -t /dev/sda1 --password sipwise 2>&1 | tee -a /tmp/grml-debootstrap.log
if [ $? -ne 0 ]; then
  echo "Error during installation of Debian squeeze." >&2
  echo "Details: mount /dev/sda1 $TARGET ; ls $TARGET/debootstrap/*.log" >&2
  exit 1
fi

sync
mount /dev/sda1 $TARGET

# removals: packages which debootstrap installs but d-i doesn't
chroot $TARGET apt-get --purge -y remove \
ca-certificates console-tools openssl tcpd xauth \
firmware-linux firmware-linux-free firmware-linux-nonfree

# get rid of automatically installed packages
chroot $TARGET apt-get --purge -y autoremove

# purge removed packages
if [[ $(chroot $TARGET dpkg --list | awk '/^rc/ {print $2}') != "" ]] ; then
  chroot $TARGET dpkg --purge $(chroot $TARGET dpkg --list | awk '/^rc/ {print $2}')
fi

# make sure installations of packages works, will be overriden later again
[ -n "$HOSTNAME" ] || HOSTNAME="kantan"
cat > $TARGET/etc/hosts << EOF
127.0.0.1       localhost
127.0.0.1 $HOSTNAME

::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

if $NGCP_INSTALLER ; then

  # add sipwise user
  chroot $TARGET adduser sipwise --disabled-login --gecos "Sipwise"
  echo "sipwise:sipwise" | chroot $TARGET chpasswd

  # install and execute ngcp-installer
  if $PRO_EDITION ; then
    # TODO - WIP!
    cat << EOT | grml-chroot $TARGET /bin/bash
PKG=ngcp-installer-pro_0.4.1_all.deb
wget http://grml:foobar@deb.sipwise.com/debs/mprokop/squeeze/\$PKG
dpkg -i \$PKG
yes | ngcp-installer \$IP1 \$IP2 \$EXTIP
RC=\$?
if [ \$RC -ne 0 ] ; then
  echo "Fatal error while running ngcp-installer:" >&2
  tail -10 /tmp/ngcp-installer.log
  exit \$RC
fi
EOT

  else # spce
    cat << EOT | grml-chroot $TARGET /bin/bash
PKG=ngcp-installer-2.2-rc1.deb
wget http://deb.sipwise.com/spce/\$PKG
dpkg -i \$PKG
yes | ngcp-installer
RC=\$?
if [ \$RC -ne 0 ] ; then
  echo "Fatal error while running ngcp-installer:" >&2
  tail -10 /tmp/ngcp-installer.log
  exit \$RC
fi
EOT
  fi

  # baby, something went wrong!
  if [ $? -ne 0 ] ; then
    echo "Error during installation of ngcp." >&2
    echo "Details: $TARGET/tmp/ngcp-installer.log" >&2
    exit 1
  fi


  # we require those packages for dkms, so do NOT remove them:
  # binutils cpp-4.3 gcc-4.3-base linux-kbuild-2.6.32
  if chroot $TARGET dkms status | grep ngcp-mediaproxy-ng ; then
    # brrrr, don't tell this anyone or i'll commit with http://whatthecommit.com/ as commit msg!
    KERNELHEADERS=$(basename $(ls -d ${TARGET}/usr/src/linux-headers*amd64 | sort -u | head -1))
    if [ -z "$KERNELHEADERS" ] ; then
       echo "Error: no kernel headers found for building the ngcp-mediaproxy-ng kernel module." >&2
       exit 1
    fi
    KERNELVERSION=${KERNELHEADERS##linux-headers-}
    NGCPVERSION=$(chroot $TARGET dkms status | grep ngcp-mediaproxy-ng | awk -F, '{print $2}' | sed 's/:.*//')
    chroot $TARGET dkms build -k $KERNELVERSION --kernelsourcedir /usr/src/$KERNELHEADERS \
           -m ngcp-mediaproxy-ng -v $NGCPVERSION
    chroot $TARGET dkms install -k $KERNELVERSION -m ngcp-mediaproxy-ng -v $NGCPVERSION
  fi

  # make sure all services are stopped
  for service in \
    apache2 \
    asterisk \
    collectd \
    kamailio \
    kamailio-lb \
    kamailio-proxy \
    mediator \
    mysql \
    ngcp-mediaproxy-ng-daemon \
    ngcp-rate-o-mat \
    ntp \
    rsyslog \
    sems ; \
  do
    chroot $TARGET /etc/init.d/$service stop || true
  done

  # nuke files
  for i in $(find "$TARGET/var/log" -type f -size +0 -not -name \*.ini 2>/dev/null); do
    :> "$i"
  done
  :>$TARGET/var/run/utmp
  :>$TARGET/var/run/wtmp

fi

# leave system in according state
cat > $TARGET/etc/hostname << EOF
${TARGET_HOSTNAME}
EOF

if [ -n "$DEVIP" ] ; then
  cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug eth0
iface eth0 inet static
        address $DEVIP
        netmask 255.255.255.0
        network 192.168.51.0
        broadcast 192.168.51.255
        gateway 192.168.51.1
        # dns-* options are implemented by the resolvconf package, if installed
        dns-nameservers 192.168.51.2 192.168.51.3
        dns-search sipwise.com
EOF
else
  cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug eth0
iface eth0 inet dhcp
EOF
fi

# set final hostname
cat > $TARGET/etc/hosts << EOF
127.0.0.1 localhost
127.0.0.1 ${TARGET_HOSTNAME}.sipwise.com ${TARGET_HOSTNAME}

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

# don't leave any mountpoints
sync
umount ${TARGET}/proc       2>/dev/null || true
umount ${TARGET}/sys        2>/dev/null || true
umount ${TARGET}/dev/pts    2>/dev/null || true
umount ${TARGET}/dev        2>/dev/null || true
chroot ${TARGET} umount -a  2>/dev/null || true
sync

# unmount chroot - what else?
umount $TARGET || umount -l $TARGET # fall back if a process is still being active

# party time! who brings the whiskey?
echo "Installation finished. \o/"

echo
if [ -n "$start_seconds" ] ; then
  SECONDS="$[$(cut -d . -f 1 /proc/uptime)-$start_seconds]" || SECONDS="unknown"
  echo "Finished on $(date) - installation was running for ${SECONDS} seconds."
fi
echo

echo "Do you want to halt the system now? Y/n"
read a
case "$a" in
  n|N)
    echo "Not halting system as requested. Please do not forget to shut down."
    ;;
  *)
    echo "Halting system as requested."
    # halt(8) is for losers
    for key in s u o ; do
      echo $key > /proc/sysrq-trigger
      sleep 2
    done
  ;;
esac

## END OF FILE #################################################################1
