#!/bin/bash
# Purpose: automatically install Debian squeeze + ngcp-installer

# Ideas:
# * rename kantan host into spce (bootoption in ISO)
# * support configuration via wget-able config file

# Never ever execute the script outside of a
# running Grml live system because partitioning
# disks might destroy data. Seriously.
if ! [ -r /etc/grml_cd ] ; then
  echo "Not running inside Grml, better safe than sorry. Sorry." >&2
  exit 1
fi

# Exit on any error. Horrible for programming,
# but be as defense as possible. Murhpy, you know.
set -e

# better safe than sorry
export LC_ALL=C
export LANG=C

# defaults
TARGET=/mnt
PRO_EDITION=false
CE_EDITION=false
NGCP_INSTALLER=false
INTERACTIVE=false
LOCAL_MIRROR=false
DHCP=false
export DISK=sda # will be configured as /dev/sda

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
if checkBootParam ngcpnw.dhcp ; then
  export DHCP=true
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

Control installation parameters:

  ngcppro          - install Pro Edition
  ngcpsp1          - install first node (Pro Edition only)
  ngcpsp2          - install second node (Pro Edition only)
  ngcpce           - install CE Edition
  nongcp           - do not install NGCP but install plain Debian only
  noinstall        - do not install neither Debian nor NGCP
  ngcpinst         - force usage of NGCP installer
  ngcpprofile=...  - download additional configuration profile (WIP)

Control target system:

  ngcpnw.dhcp      - use DHCP as network configuration in installed system
                     NOTE: defaults to IP address of installed node in Pro Edition
  ngcphostname=... - hostname of installed system (defaults to ngcp/sp[1,2])
                     NOTE: do NOT use when installing Pro Edition, WIP!
  ngcpeiface=ethX  - external interface device (e.g. eth0)
  ngcpip1=...      - IP address of first node
  ngcpip2=...      - IP address of second node
  ngcpeaddr=...    - Cluster IP address

The command line options correspond with the available bootoptions.
Command line overrides any present bootoption.

Usage examples:


  # ngcp-deployment ngcpce ngcpnw.dhcp

  # netcardconfig # configure eth0 with static configuration
  # ngcp-deployment ngcppro ngcpsp1 ngcpip1=192.168.1.101 \\
      ngcpip2=192.168.1.102 ngcpeaddr=192.168.1.103 ngcpeiface=b0 ngcpmcast=226.94.1.1

  # netcardconfig # configure eth0 with static configuration
  # ngcp-deployment ngcppro ngcpsp2 ngcpip1=192.168.1.101 \\
      ngcpip2=192.168.1.102 ngcpeaddr=192.168.1.103 ngcpeiface=b0 ngcpmcast=226.94.1.1
"
}

for param in $* ; do
  case $param in
    *-h*|*--help*|*help*) usage ; exit 0;;
    *ngcpsp1*) ROLE=sp1 ; PRO_EDITION=true; CE_EDITION=false ;;
    *ngcpsp2*) ROLE=sp2 ; TARGET_HOSTNAME=sp2; PRO_EDITION=true; CE_EDITION=false ;;
    *ngcppro*) PRO_EDITION=true; CE_EDITION=false ; NGCP_INSTALLER=true ;;
    *ngcpce*) PRO_EDITION=false; CE_EDITION=true ; TARGET_HOSTNAME=spce ; ROLE='' ; NGCP_INSTALLER=true ;;
    *nongcp*) NGCP_INSTALLER=false;;
    *nodebian*) DEBIAN_INSTALLER=false;; # TODO
    *noinstall*) NGCP_INSTALLER=false; DEBIAN_INSTALLER=false;;
    *ngcpinst*) NGCP_INSTALLER=true;;
    *ngcphostname=*) TARGET_HOSTNAME=$(echo $param | sed 's/ngcphostname=//');;
    *ngcpprofile=*) PROFILE=$(echo $param | sed 's/ngcpprofile=//');;
    *ngcpeiface=*) export EIFACE=$(echo $param | sed 's/ngcpeiface=//');;
    *ngcpeaddr=*) export EADDR=$(echo $param | sed 's/ngcpeaddr=//');;
    *ngcpip1=*) export IP1=$(echo $param | sed 's/ngcpip1=//');;
    *ngcpip2=*) export IP2=$(echo $param | sed 's/ngcpip2=//');;
    *ngcpmcast=*) export MCASTADDR=$(echo $param | sed 's/ngcpmcast=//');;
    *ngcpnw.dhcp*) export DHCP=true;;
  esac
  shift
done

if ! $NGCP_INSTALLER ; then
  unset PRO_EDITION
  unset CE_EDITION
  unset ROLE
fi

echo "Deployment Settings:

  Install ngcp:      $NGCP_INSTALLER
  Installer - pro:   $PRO_EDITION
  Installer - ce:    $CE_EDITION
  Hostname:          $TARGET_HOSTNAME
  Host Role:         $ROLE
  Profile:           $PROFILE

  1st host IP:       $IP1
  2nd host IP:       $IP2
  Ext host IP:       $EADDR
  Multicast addr:    $MCASTADDR
  Network iface:     $EIFACE
  Use DHCP in host:  $DHCP

  $CHASSIS
"

if $INTERACTIVE ; then
  echo "WARNING: Execution will override any existing data!"
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

# TODO
# if checkBootParam ngcpfirmware ; then
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
#
# wget http://delivery04.dhe.ibm.com/sar/CMA/XSA/02gcs/1/ibm_utl_asu_asut72l_linux_x86-64.tgz
# unp ibm_utl_asu_asut72l_linux_x86-64.tgz
# ./asu64 set BootOrder.BootOrder 'Hard Disk 0=USB Storage=CD/DVD Rom'

# run in according environment only
if [[ $(imvirt) == "Physical" ]] ; then
  # TODO / FIXME  hardcoded for now, needs better check to support !ServeRAID[-MR10ie] as well
  if ! grep -q 'ServeRAID' /sys/block/${DISK}/device/model ; then
    echo "Error: /dev/${DISK} does not look like a ServeRAID disk." >&2
    echo "Exiting to avoid possible data damage." >&2
    exit 1
  fi
else
  # make sure it runs only within qemu/kvm
  if ! grep -q 'QEMU HARDDISK' /sys/block/${DISK}/device/model ; then
    echo "Error: /dev/${DISK} does not look like a virtual disk." >&2
    echo "Exiting to avoid possible data damage." >&2
    exit 1
  fi
fi

# measure time of installation procedure - everyone loves stats!
start_seconds=$(cut -d . -f 1 /proc/uptime)

# when using ip=....:$HOSTNAME:eth0:off file /etc/hosts doesn't contain the
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

# relevant only while deployment, will be overriden later
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

## partition disk
# physical installation
if [[ $(imvirt) == "Physical" ]] || $PRO_EDITION ; then
  # remove existing partitioning
  #  dd if=/dev/zero of=/dev/${DISK} bs=512 count=1
  #  partprobe /dev/${DISK} ; sync

  parted -s /dev/${DISK} mktable msdos
  # hw-raid with rootfs + swap partition
  parted -s /dev/${DISK} 'mkpart primary ext4 2048s 95%'
  parted -s /dev/${DISK} 'mkpart primary linux-swap 95% -1'

else # virtual installation
  # just one disk, assuming VM installation without swap partition
  # do not depend on static value (like 33554432 for 16GB)
  disksize=$(cat /sys/block/${DISK}/size)
  disksize=$(echo $(($disksize-2048))) # proper alignment for grub and performance

  sfdisk /dev/${DISK} <<ENDDISK
# partition table of /dev/${DISK}
unit: sectors

/dev/${DISK}1 : start=     2048, size= ${disksize}, Id=83
/dev/${DISK}2 : start=        0, size=        0, Id= 0
/dev/${DISK}3 : start=        0, size=        0, Id= 0
/dev/${DISK}4 : start=        0, size=        0, Id= 0
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
#acpi acpid acpi-support-base # installed in PRO
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

# support acpi
acpi acpid acpi-support-base
EOF
fi

# provide Debian mirror
if [ -d /srv/mirror/debs ] ; then
  echo "Debian directory /srv/mirror/debs found."
  cd /srv/mirror/
  if ! [ -d /srv/mirror/debian ] ; then
    echo "Setting up configuration for reprepro."
    mkdir -p /srv/mirror/debian/conf/
    cat > /srv/mirror/debian/conf/distributions << EOF
Origin: Debian
Label: Debian
Suite: stable
Version: 6.0
Codename: squeeze
Architectures: amd64 source
Components: main contrib non-free
Description: Debian Mirror
Log: logfile
EOF

    echo "Building local Debian mirror based on packages found in /srv/mirror/debs."
    for f in /srv/mirror/debs/*deb ; do
      reprepro --silent -b /srv/mirror/debian includedeb squeeze "$f"
    done
  fi

  # run local webserver
  if ps aux | grep -q '[p]ython -m SimpleHTTPServer' ; then
    kill $(ps aux | grep '[p]ython -m SimpleHTTPServer' | awk '{print $2}')
  fi
  python -m SimpleHTTPServer &>/dev/null &
  sleep 1
  if wget -O /dev/null http://localhost:8000/debian/dists/squeeze/main/binary-amd64/Packages &>/dev/null ; then
    echo "Found functional local mirror, using for first stage installation."
    MIRROR="http://localhost:8000/debian/"
    LOCAL_MIRROR=true
  fi
fi

if [ -z "$MIRROR" ] ; then
  MIRROR="http://debian.inode.at/debian/"
fi

if $LOCAL_MIRROR ; then
  mkdir -p /etc/debootstrap/pre-scripts
  cat > /etc/debootstrap/pre-scripts/adjust_sources_list << EOT
cat > \$MNTPOINT/etc/apt/sources.list << EOF
# deployed via ngcp-deployment [net]script
# to override partial-only local mirror
deb http://debian.inode.at/debian squeeze main contrib non-free
deb http://security.debian.org squeeze/updates main contrib non-free
EOF
chroot \$MNTPOINT apt-get -y update
chroot \$MNTPOINT apt-get -y upgrade
EOT
  chmod +x /etc/debootstrap/pre-scripts/adjust_sources_list
fi

# install Debian squeeze
echo y | grml-debootstrap \
  --grub /dev/${DISK} \
  --hostname "${TARGET_HOSTNAME}" \
  --mirror "$MIRROR" \
  --debopt '--no-check-gpg' \
  --pre-scripts '/etc/debootstrap/pre-scripts' \
  --keep_src_list \
  -r 'squeeze' \
  -t "/dev/${DISK}1" \
  --password 'sipwise' 2>&1 | tee -a /tmp/grml-debootstrap.log

if [ ${PIPESTATUS[1]} -ne 0 ]; then
  echo "Error during installation of Debian squeeze." >&2
  echo "Details: mount /dev/${DISK}1 $TARGET ; ls $TARGET/debootstrap/*.log" >&2
  exit 1
fi

sync
mount /dev/${DISK}1 $TARGET

# removals: packages which debootstrap installs but d-i doesn't
chroot $TARGET apt-get --purge -y remove \
ca-certificates console-tools openssl tcpd xauth

if $PRO_EDITION ; then
  echo "Pro edition: keeping firmware* packages."
else
  chroot $TARGET apt-get --purge -y remove \
  firmware-linux firmware-linux-free firmware-linux-nonfree
fi

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
    export ROLE=$ROLE

    # hopefully set via bootoption/cmdline,
    # otherwise fall back to hopefully-safe-defaults
    [ -n "$IP1" ] || export IP1=192.168.1.101
    [ -n "$IP2" ] || export IP2=192.168.1.102
    [ -n "$EADDR" ] || export EADDR=192.168.1.103
    [ -n "$EIFACE" ] || export EIFACE=b0
    [ -n "$MCASTADDR" ] || export MCASTADDR=226.94.1.1

    cat << EOT | grml-chroot $TARGET /bin/bash
PKG=ngcp-installer-latest.deb
wget http://deb.sipwise.com/sppro/\$PKG
dpkg -i \$PKG
ngcp-installer \$ROLE \$IP1 \$IP2 \$EADDR \$EIFACE \$MCASTADDR
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

if $DHCP ; then
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
else
  # assume host system has a valid configuration
  cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

auto b0
iface b0 inet static
        address $(ifdata -pa eth0)
        netmask $(ifdata -pn eth0)
        gateway $(route -n | awk '/^0\.0\.0\.0/{print $2; exit}')
        dns-nameservers $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | xargs echo -n)
        bond-slaves eth0 eth1
        bond_mode 802.3ad
        bond_miimon 100
        bond_lacp_rate 1

# Example:
# allow-hotplug eth0
# iface eth0 inet static
#         address 192.168.1.101
#         netmask 255.255.255.0
#         network 192.168.1.0
#         broadcast 192.168.1.255
#         gateway 192.168.1.1
#         # dns-* options are implemented by the resolvconf package, if installed
#         dns-nameservers 195.58.160.194 195.58.161.122
#         dns-search sipwise.com
EOF

  # provide example configuration
  cat  > $TARGET/etc/network/interfaces.examples << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug eth0
iface eth0 inet static
        address 192.168.1.101
        netmask 255.255.255.0
        network 192.168.1.0
        broadcast 192.168.1.255
        gateway 192.168.1.1
        # dns-* options are implemented by the resolvconf package, if installed
        dns-nameservers 195.58.160.194 195.58.161.122
        dns-search sipwise.com

# auto b0
# iface b0 inet static
#         address 192.168.1.101
#         netmask 255.255.255.0
#         gateway 192.168.1.1
#         dns-nameservers 195.58.160.194 195.58.161.122
#         bond-slaves eth0 eth1
#         bond_mode 802.3ad
#         bond_miimon 100
#         bond_lacp_rate 1

# auto eth1
# iface eth1 inet dhcp
EOF
fi

# finalise hostname configuration
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

# append hostnames of sp1/sp2 so they can talk to each other
# in the HA setup
if $PRO_EDITION ; then
  cat >> $TARGET/etc/hosts << EOF
$IP1 sp1
$IP2 sp2
EOF
fi

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

if $PRO_EDITION ; then
  echo "Execute:

  asu64 set BootOrder.BootOrder 'Hard Disk 0=USB Storage=CD/DVD Rom'

to boot from hard disk by default or

  asu64 set BootOrder.BootOrder 'USB Storage=Hard Disk 0=CD/DVD Rom'

to boot from USB storage by default."
fi

echo "Do you want to [r]eboot or [h]alt the system now? (Press any other key to cancel.)"
unset a
read a
case "$a" in
  r)
    echo "Rebooting system as requested."
    # reboot is for losers
    for key in s u b ; do
      echo $key > /proc/sysrq-trigger
      sleep 2
    done
  ;;
  h)
    echo "Halting system as requested."
    # halt(8) is for losers
    for key in s u o ; do
      echo $key > /proc/sysrq-trigger
      sleep 2
    done
  ;;
  *)
    echo "Not halting system as requested. Please do not forget to reboot."
    ;;
esac

## END OF FILE #################################################################1
