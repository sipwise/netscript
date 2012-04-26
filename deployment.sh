#!/bin/bash
# Purpose: automatically install Debian + sip:provider platform
################################################################################
# $Id$
# $Rev$
################################################################################

# set version to svn revision information, initially enabled via
# svn propset svn:keywords 'Id Revision' deployment.sh
SCRIPT_VERSION="$Rev$"

# not set? then fall back to timestamp of execution
if [ -z "$SCRIPT_VERSION" ] || [ "$SCRIPT_VERSION" = '$' ] ; then
  SCRIPT_VERSION=$(date +%s) # seconds since 1970-01-01 00:00:00 UTC
else # we just want the ID from something like "$Rev$"
  SCRIPT_VERSION=$(echo $SCRIPT_VERSION | awk '{print $2}')
fi

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
DEFAULT_INSTALL_DEV=eth0
DEFAULT_IP1=192.168.255.251
DEFAULT_IP2=192.168.255.252
DEFAULT_INTERNAL_NETMASK=255.255.255.248
DEFAULT_MCASTADDR=226.94.1.1
TARGET=/mnt
PRO_EDITION=false
CE_EDITION=false
NGCP_INSTALLER=false
PUPPET=''
INTERACTIVE=false
DHCP=false
LOGO=true
BONDING=false
LINUX_HA3=false
TRUNK_VERSION=false
DEBIAN_RELEASE=squeeze
KANTAN=false
HALT=false
if [ -L /sys/block/vda ] ; then
  export DISK=vda # will be configured as /dev/vda
else
  export DISK=sda # will be configured as /dev/sda
fi

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

# load ":"-separated nfs ip into array BP[client-ip], BP[server-ip], ...
# ip=<client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>
# $1: Array name (needs "declare -A BP" before call), $2: ip=... string
loadNfsIpArray() {
  [ -n "$1" ] && [ -n "$2" ] || return 0
  local IFS=":"
  local ind=(client-ip server-ip gw-ip netmask hostname device autoconf)
  local i
  for i in $2 ;
  do
    #  eval echo ${ind[$n]} - $i
    eval $1[${ind[n++]}]=$i
  done
  [ "$n" == "7" ] && return 0 || return 1
}

logo() {
    cat <<-EOF
+++ Grml-Sipwise Deployment +++

$(cat /etc/grml_version)
Host IP(s): $(ip-screen) | Deployment version: $SCRIPT_VERSION
$(lscpu | awk '/^CPU\(s\)/ {print $2}') CPU(s) | $(/usr/bin/gawk '/MemTotal/{print $2}' /proc/meminfo)kB RAM | $CHASSIS

Install ngcp: $NGCP_INSTALLER | Install pro: $PRO_EDITION | Install ce: $CE_EDITION
Installing $SP_VERSION_STR platform using installer version $INSTALLER_VERSION_STR
Install IP: $INSTALL_IP | Started deployment at $(date)

EOF
}
### }}}

# provide method to boot live system without running installer
if checkBootParam noinstall ; then
  echo "Exiting as requested via bootoption noinstall."
  exit 0
fi

if checkBootParam nocolorlogo ; then
  LOGO=false
fi

if checkBootParam ngcphav3 ; then
  LINUX_HA3=true
  PRO_EDITION=true
fi

if checkBootParam ngcpnobonding ; then
  BONDING=false
fi

if checkBootParam ngcpbonding ; then
  BONDING=true
fi

if checkBootParam ngcptrunk ; then
  TRUNK_VERSION=true
fi
export TRUNK_VERSION # make sure it's available within grml-chroot subshell

## detect environment {{{
if dmidecode| grep -q 'Rack Mount Chassis' ; then
  CHASSIS="Running in Rack Mounted Chassis."
elif dmidecode| grep -q 'Location In Chassis'; then
 CHASSIS="Running in blade chassis $(dmidecode| awk '/Location In Chassis/ {print $4}')"
 PRO_EDITION=true
else
 CHASSIS="No physical chassis found"
fi

if checkBootParam ngcpinst || checkBootParam ngcpsp1 || checkBootParam ngcpsp2 || \
  checkBootParam ngcppro || checkBootParam ngcpce ; then
  NGCP_INSTALLER=true
fi

if checkBootParam ngcpce ; then
  CE_EDITION=true
fi

if checkBootParam ngcppro || checkBootParam ngcpsp1 || checkBootParam ngcpsp2 ; then
  PRO_EDITION=true
fi

if "$PRO_EDITION" ; then
  ROLE=sp1

  if checkBootParam ngcpsp2 ; then
    ROLE=sp2
  fi
fi

if checkBootParam "puppetenv" ; then
  # we expected to get the environment for puppet
  PUPPET=$(getBootParam puppetenv)
fi

# test unfinished releases against
# "http://deb.sipwise.com/autobuild/ release-$AUTOBUILD_RELEASE"
if checkBootParam ngcpautobuildrelease ; then
  AUTOBUILD_RELEASE=$(getBootParam ngcpautobuildrelease)
  export SKIP_SOURCES_LIST=true # make sure it's available within grml-chroot subshell
fi

# existing ngcp releases (like 2.2) with according repository and installer
if checkBootParam ngcpvers ; then
  SP_VERSION=$(getBootParam ngcpvers)
fi

# specific ngcp-installer version
if checkBootParam ngcpinstvers ; then
  INSTALLER_VERSION=$(getBootParam ngcpinstvers)
fi

if checkBootParam nongcp ; then
  echo "Will not execute ngcp-installer as requested via bootoption nongcp."
  NGCP_INSTALLER=false
fi

# configure static network in installed system?
if checkBootParam ngcpnw.dhcp ; then
  DHCP=true
fi

if checkBootParam ngcphostname ; then
  TARGET_HOSTNAME="$(getBootParam ngcphostname)" || true
fi

if checkBootParam ngcpip1 ; then
  IP1=$(getBootParam ngcpip1)
fi

if checkBootParam ngcpip2 ; then
  IP2=$(getBootParam ngcpip2)
fi

if checkBootParam ngcpeaddr ; then
  EADDR=$(getBootParam ngcpeaddr)
fi

if checkBootParam ngcpeiface ; then
  EIFACE=$(getBootParam ngcpeiface)
fi

if checkBootParam ngcpmcast ; then
  MCASTADDR=$(getBootParam ngcpmcast)
fi

if checkBootParam ngcpcrole ; then
  CROLE=$(getBootParam ngcpcrole)
fi

if checkBootParam ngcpcmaster ; then
  CMASTER=$(getBootParam ngcpcmaster)
fi

# site specific profile file
if checkBootParam netscript ; then
  NETSCRIPT_SERVER="$(dirname $(getBootParam netscript))"
fi

if checkBootParam ngcpprofile && [ -n "$NETSCRIPT_SERVER" ] ; then
  PROFILE="$(getBootParam ngcpprofile)"

  if [ -z "$PROFILE" ] ; then
    echo "Error: No argument for ngcpprofile found, can not continue." >&2
    exit 1
  fi
fi

if checkBootParam kantan ; then
  KANTAN=true
fi

if checkBootParam ngcphalt ; then
  HALT=true
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
  echo "$0 - automatically deploy Debian ${DEBIAN_RELEASE} and (optionally) ngcp ce/pro.

Control installation parameters:

  ngcppro          - install Pro Edition
  ngcpsp1          - install first node (Pro Edition only)
  ngcpsp2          - install second node (Pro Edition only)
  ngcpce           - install CE Edition
  ngcpcrole=...    - server role (Carrier)
  ngcpcmaster=...  - IP of master server (Carrier)
  ngcpvers=...     - install specific SP/CE version
  nongcp           - do not install NGCP but install plain Debian only
  noinstall        - do not install neither Debian nor NGCP
  ngcpinst         - force usage of NGCP installer
  ngcpinstvers=... - use specific NGCP installer version
  ngcpprofile=...  - download additional configuration profile (WIP)

Control target system:

  ngcpnw.dhcp      - use DHCP as network configuration in installed system
  ngcphostname=... - hostname of installed system (defaults to ngcp/sp[1,2])
                     NOTE: do NOT use when installing Pro Edition!
  ngcpeiface=...   - external interface device (defaults to eth0)
  ngcpip1=...      - IP address of first node
  ngcpip2=...      - IP address of second node
  ngcpeaddr=...    - Cluster IP address

The command line options correspond with the available bootoptions.
Command line overrides any present bootoption.

Usage examples:

  # ngcp-deployment ngcpce ngcpnw.dhcp

  # netcardconfig # configure eth0 with static configuration
  # ngcp-deployment ngcppro ngcpsp1

  # netcardconfig # configure eth0 with static configuration
  # ngcp-deployment ngcppro ngcpsp2
"
}

for param in $* ; do
  case $param in
    *-h*|*--help*|*help*) usage ; exit 0;;
    *ngcpsp1*) ROLE=sp1 ; TARGET_HOSTNAME=sp1; PRO_EDITION=true; CE_EDITION=false ; NGCP_INSTALLER=true ;;
    *ngcpsp2*) ROLE=sp2 ; TARGET_HOSTNAME=sp2; PRO_EDITION=true; CE_EDITION=false ; NGCP_INSTALLER=true ;;
    *ngcppro*) PRO_EDITION=true; CE_EDITION=false ; NGCP_INSTALLER=true ;;
    *ngcpce*) PRO_EDITION=false; CE_EDITION=true ; TARGET_HOSTNAME=spce ; ROLE='' ; NGCP_INSTALLER=true ;;
    *ngcpvers=*) SP_VERSION=$(echo $param | sed 's/ngcpvers=//');;
    *nongcp*) NGCP_INSTALLER=false;;
    *nodebian*) DEBIAN_INSTALLER=false;; # TODO
    *noinstall*) NGCP_INSTALLER=false; DEBIAN_INSTALLER=false;;
    *ngcpinst*) NGCP_INSTALLER=true;;
    *ngcpinstvers=*) INSTALLER_VERSION=$(echo $param | sed 's/ngcpinstvers=//');;
    *ngcphostname=*) TARGET_HOSTNAME=$(echo $param | sed 's/ngcphostname=//');;
    *ngcpprofile=*) PROFILE=$(echo $param | sed 's/ngcpprofile=//');;
    *ngcpeiface=*) EIFACE=$(echo $param | sed 's/ngcpeiface=//');;
    *ngcpeaddr=*) EADDR=$(echo $param | sed 's/ngcpeaddr=//');;
    *ngcpip1=*) IP1=$(echo $param | sed 's/ngcpip1=//');;
    *ngcpip2=*) IP2=$(echo $param | sed 's/ngcpip2=//');;
    *ngcpmcast=*) MCASTADDR=$(echo $param | sed 's/ngcpmcast=//');;
    *ngcpcrole=*) CROLE=$(echo $param | sed 's/ngcpcrole=//');;
    *ngcpcmaster=*) CMASTER=$(echo $param | sed 's/ngcpcmaster=//');;
    *ngcpnw.dhcp*) DHCP=true;;
    *ngcphav3*) LINUX_HA3=true; PRO_EDITION=true;;
    *ngcpnobonding*) BONDING=false;;
    *ngcpbonding*) BONDING=true;;
    *ngcphalt*) HALT=true;;
  esac
  shift
done

if ! "$NGCP_INSTALLER" ; then
  PRO_EDITION=false
  CE_EDITION=false
  unset ROLE
fi

# load site specific profile if specified
if [ -n "$PROFILE" ] && [ -n "$NETSCRIPT_SERVER" ] ; then
  getconfig() {
    wget -r --no-parent --timeout=10 --dns-timeout=10  --connect-timeout=10 --tries=1 \
         --read-timeout=10 ${NETSCRIPT_SERVER}/$PROFILE/ && return 0 || return 1
  }

  echo "Trying to get ${NETSCRIPT_SERVER}/$PROFILE/*"
  counter=10
  while ! getconfig && [[ "$counter" != 0 ]] ; do
    echo -n "Sleeping for 1 second and trying to get config again... "
    counter=$(( counter-1 ))
    echo "$counter tries left" ; sleep 1
  done

  DOWNLOADDIR=$(echo ${NETSCRIPT_SERVER}/$PROFILE | sed 's|^http://||')
  if [ -d "$DOWNLOADDIR" ] ; then
    if [ -s "$DOWNLOADDIR/default.sh" ] ; then
      rm -rf $DOWNLOADDIR/index.html*
      mv $DOWNLOADDIR/* ./
      rmdir -p $DOWNLOADDIR
      echo "Loading profile $PROFILE"
      . default.sh
    else
      echo "Error: No default.sh in profile $PROFILE from $NETSCRIPT_SERVER" >&2
      rm -rf $DOWNLOADDIR/*
      rmdir -p $DOWNLOADDIR
      exit 1
    fi
  else
    echo "Error: Could not get profile $PROFILE from $NETSCRIPT_SERVER" >&2
    exit 1
  fi
fi

# when using ip=....:$HOSTNAME:eth0:off file /etc/hosts doesn't contain the
# hostname by default, avoid warning/error messages in the host system
# and use it for IP address check in pro edition
if [ -z "$TARGET_HOSTNAME" ] ; then
  if "$PRO_EDITION" ; then
    TARGET_HOSTNAME="$ROLE"
  fi

  if "$CE_EDITION" ; then
    TARGET_HOSTNAME="spce"
  fi

  # if we don't install ngcp ce/pro but
  # $HOSTNAME is set via ip=.... then
  # take it, otherwise fall back to safe default
  if [ -z "$TARGET_HOSTNAME" ] ; then
    if [ -n "$HOSTNAME" ] ; then
      TARGET_HOSTNAME="$HOSTNAME"
    else
      TARGET_HOSTNAME="debian"
    fi
  fi
fi

# get install device from "ip=<client-ip:<srv-ip>:..." boot arg
if checkBootParam ip ; then
  declare -A IP_ARR
  if loadNfsIpArray IP_ARR $(getBootParam ip) ; then
    INSTALL_DEV=${IP_ARR[device]}
  fi
fi

# set reasonable install device from other source
if [ -z "$INSTALL_DEV" ] ; then
  if [ -n "$EIFACE" ] ; then
    INSTALL_DEV=$EIFACE
  else
    INSTALL_DEV=$DEFAULT_INSTALL_DEV
  fi
fi
INSTALL_IP="$(ifdata -pa $INSTALL_DEV)"

# final external device and IP are same as installation, if not set in profile
[ -n "$EXTERNAL_DEV" ] || EXTERNAL_DEV=$INSTALL_DEV
[ -n "$EXTERNAL_IP" ] || EXTERNAL_IP=$INSTALL_IP

# hopefully set via bootoption/cmdline,
# otherwise fall back to hopefully-safe-defaults
# make sure the internal device (configured later) is not statically assigned,
# since when booting with ip=....eth1:off then the internal device needs to be eth0
if "$PRO_EDITION" ; then
  if [ -z "$INTERNAL_DEV" ] ; then
    INTERNAL_DEV='eth1'
    if [[ "$EXTERNAL_DEV" = "eth1" ]] ; then
      INTERNAL_DEV='eth0'
    fi
  fi
  [ -n "$IP1" ] || IP1=$DEFAULT_IP1
  [ -n "$IP2" ] || IP2=$DEFAULT_IP2
  case "$ROLE" in
    sp1) INTERNAL_IP=$IP1 ;;
    sp2) INTERNAL_IP=$IP2 ;;
  esac
  [ -n "$INTERNAL_NETMASK" ] || INTERNAL_NETMASK=$DEFAULT_INTERNAL_NETMASK
  [ -n "$MCASTADDR" ] || MCASTADDR=$DEFAULT_MCASTADDR
fi

[ -n "$EIFACE" ] || EIFACE=$INSTALL_DEV
[ -n "$EADDR" ] || EADDR=$INSTALL_IP

# needed as environment vars for ngcp-installer
if "$PRO_EDITION" ; then
  export ROLE
  export IP1
  export IP2
  export EADDR
  export EIFACE
  export MCASTADDR
  export DHCP
else
  export EIFACE
  export DHCP
fi

if "$PRO_EDITION" ; then
  case "$SP_VERSION" in
    2.2) INSTALLER_VERSION="0.4.7" ;;
    2.3) INSTALLER_VERSION="0.5.3" ;;
    2.4) INSTALLER_VERSION="0.6.3";;
    2.5-rc1) INSTALLER_VERSION="0.6.4";;
    2.5) INSTALLER_VERSION="0.7.2";;
  esac
elif "$CE_EDITION" ; then
  case "$SP_VERSION" in
    # we do not have a local mirror for lenny, so disable it
    2.1) INSTALLER_VERSION="0.3.2" ; DEBIAN_RELEASE="lenny" ;;
    2.2) INSTALLER_VERSION="0.4.7";;
    2.4) INSTALLER_VERSION="0.6.3";;
    2.5) INSTALLER_VERSION="0.7.2";;
  esac
fi

### echo settings
[ -n "$SP_VERSION" ] && SP_VERSION_STR=$SP_VERSION \
    || SP_VERSION_STR="<latest>"
[ -n "$INSTALLER_VERSION" ] && INSTALLER_VERSION_STR=$INSTALLER_VERSION \
    || INSTALLER_VERSION_STR="<latest>"

echo "Deployment Settings:

  Install ngcp:      $NGCP_INSTALLER
  Installer - pro:   $PRO_EDITION
  Installer - ce:    $CE_EDITION
  Version:           $SP_VERSION_STR
  Installer vers.:   $INSTALLER_VERSION_STR
  Install Hostname:  $HOSTNAME
  Install NW iface:  $INSTALL_DEV
  Install IP:        $INSTALL_IP

  Target Hostname:   $TARGET_HOSTNAME
  Host Role:         $ROLE
  Host Role Carrier: $CROLE
  Profile:           $PROFILE
  Master Server:     $CMASTER

  External NW iface: $EXTERNAL_DEV
  Ext host IP:       $EXTERNAL_IP
  Ext cluster iface: $EIFACE
  Ext cluster IP:    $EADDR
  Multicast addr:    $MCASTADDR
  Use DHCP in host:  $DHCP
  Internal NW iface: $INTERNAL_DEV
  Int sp1 host IP:   $IP1
  Int sp2 host IP:   $IP2
  Int netmask:       $INTERNAL_NETMASK

  $CHASSIS
" | tee -a /tmp/installer-settings.txt

if "$INTERACTIVE" ; then
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

##### all parameters set #######################################################

# measure time of installation procedure - everyone loves stats!
start_seconds=$(cut -d . -f 1 /proc/uptime)

if "$KANTAN" ; then
  if [[ "$SHLVL" == "2" ]] || [ -n "${NETSCRIPT:-}" ] ; then
    echo "starting installation process at $(date)" | telnet 10.0.2.2 8888 || true
  fi
fi

if "$LOGO" ; then
  reset
  # color
  echo -ne "\ec\e[1;32m"
  logo
  # number of lines
  echo -ne "\e[10;0r"
  # reset color
  echo -ne "\e[9B\e[1;m"
fi

if "$PRO_EDITION" ; then
   # internal network (default on eth1)
   if ifconfig "$INTERNAL_DEV" &>/dev/null ; then
     ifconfig "$INTERNAL_DEV" $INTERNAL_IP netmask $INTERNAL_NETMASK
   else
     echo "Error: no $INTERNAL_DEV NIC found, can not deploy internal network. Exiting." >&2
     exit 1
   fi

  # ipmi on IBM hardware
  if ifconfig usb0 &>/dev/null ; then
    ifconfig usb0 169.254.1.102 netmask 255.255.0.0
  fi
fi

# TODO - hardcoded for now, to avoid data damage
check_for_supported_disk() {
  if grep -q 'ServeRAID' /sys/block/${DISK}/device/model ; then
    return 0
  fi

  # IBM System x3250 M3
  if grep -q 'Logical Volume' /sys/block/${DISK}/device/model && \
    grep -q "LSILOGIC" /sys/block/${DISK}/device/vendor ; then
    return 0
  fi

  if grep -q 'PERC H700' /sys/block/${DISK}/device/model && \
    grep -q "DELL" /sys/block/${DISK}/device/vendor ; then
    return 0
  fi

  # no match so far?
  return 1
}

# run in according environment only
if [[ $(imvirt 2>/dev/null) == "Physical" ]] ; then

  if ! check_for_supported_disk ; then
    echo "Error: /dev/${DISK} does not look like a VirtIO, ServeRAID, LSILOGIC or PowerEdge disk/controller." >&2
    echo "Exiting to avoid possible data damage." >&2
    exit 1
  fi

else
  # make sure it runs only within qemu/kvm
  if [[ "$DISK" == "vda" ]] && readlink -f /sys/block/vda/device | grep -q 'virtio' ; then
    echo "Looks like a virtio disk, ok."
  elif grep -q 'QEMU HARDDISK' /sys/block/${DISK}/device/model ; then
    echo "Looks like a QEMU harddisk, ok."
  elif grep -q 'VBOX HARDDISK' /sys/block/${DISK}/device/model ; then
    echo "Looks like a VBOX harddisk, ok."
  else
    echo "Error: /dev/${DISK} does not look like a virtual disk." >&2
    echo "Exiting to avoid possible data damage." >&2
    echo "Note: imvirt output is $(imvirt)" >&2
    exit 1
  fi
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
$INSTALL_IP $HOSTNAME
EOF
fi

# remote login ftw
/etc/init.d/ssh start >/dev/null &
echo "root:sipwise" | chpasswd

## partition disk
parted -s /dev/${DISK} mktable msdos
# hw-raid with rootfs + swap partition
parted -s /dev/${DISK} 'mkpart primary ext4 2048s 95%'
parted -s /dev/${DISK} 'mkpart primary linux-swap 95% -1'
sync

SWAP_PARTITION="/dev/${DISK}2"
echo "Initialising swap partition $SWAP_PARTITION"
mkswap "$SWAP_PARTITION"

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

# required e.g. for "Broadcom NetXtreme II BCM5709S Gigabit Ethernet"
# lacking the firmware will result in non-working network on
# too many physical server systems, so just install it by default
firmware-bnx2
firmware-bnx2x

# required for dkms
linux-headers-2.6-amd64

# support acpi (d-i installs them as well)
acpi acpid acpi-support-base

# be able to login on the system, even if just installing plain Debian
openssh-server

# packages d-i installs but we ignore/skip:
#discover
#gettext-base
#installation-report
#kbd
#laptop-detect
#os-prober
EOF

if "$PRO_EDITION" ; then
  cat >> /etc/debootstrap/packages << EOF
# support 32bit binaries, e.g. for firmware upgrades
ia32-libs
EOF
fi

if [ -n "$PUPPET" ] ; then
  cat >> /etc/debootstrap/packages << EOF
# for interal use at sipwise
openssh-server
puppet
EOF
fi

# lenny is no longer available on default Debian mirrors
case "$DEBIAN_RELEASE" in
  lenny)
    MIRROR='http://archive.debian.org/debian/'
    ;;
  *)
    MIRROR='http://debian.inode.at/debian/'
    ;;
esac

# install Debian
echo y | grml-debootstrap \
  --grub /dev/${DISK} \
  --hostname "${TARGET_HOSTNAME}" \
  --mirror "$MIRROR" \
  --debopt '--no-check-gpg' $EXTRA_DEBOOTSTRAP_OPTS \
  -r "$DEBIAN_RELEASE" \
  -t "/dev/${DISK}1" \
  --password 'sipwise' 2>&1 | tee -a /tmp/grml-debootstrap.log

if [ ${PIPESTATUS[1]} -ne 0 ]; then
  echo "Error during installation of Debian ${DEBIAN_RELEASE}." >&2
  echo "Details: mount /dev/${DISK}1 $TARGET ; ls $TARGET/debootstrap/*.log" >&2
  exit 1
fi

sync
mount /dev/${DISK}1 $TARGET

# provide useable swap partition
SWAP_PARTITION="/dev/${DISK}2"
echo "Enabling swap partition $SWAP_PARTITION via /etc/fstab"
cat >> "${TARGET}/etc/fstab" << EOF
$SWAP_PARTITION                      none           swap       sw,pri=0  0  0
EOF

# removals: packages which debootstrap installs but d-i doesn't
chroot $TARGET apt-get --purge -y remove \
ca-certificates console-tools openssl tcpd xauth

if "$PRO_EDITION" ; then
  echo "Pro edition: keeping firmware* packages."
else
  chroot $TARGET apt-get --purge -y remove \
  firmware-linux firmware-linux-free firmware-linux-nonfree || true
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

if "$PRO_EDITION" ; then
  if [ -n "$CROLE" ] ; then
    echo "Writing $CROLE to /etc/ngcp_ha_role"
    echo $CROLE > $TARGET/etc/ngcp_ha_role
  else
    echo "No role definition set, not creating /etc/ngcp_ha_role"
  fi

  if [ -n "$CMASTER" ] ; then
    echo "Writing $CMASTER to /etc/ngcp_ha_master"
    echo $CMASTER > $TARGET/etc/ngcp_ha_master
  else
    echo "No mgmgt master set, not creating /etc/ngcp_ha_master"
  fi
fi

if "$PRO_EDITION" && [[ $(imvirt) != "Physical" ]] ; then
  echo "Generating udev persistent net rules."
  INT_MAC=$(udevadm info -a -p /sys/class/net/${INTERNAL_DEV} | awk -F== '/ATTR{address}/ {print $2}')
  EXT_MAC=$(udevadm info -a -p /sys/class/net/${EXTERNAL_DEV} | awk -F== '/ATTR{address}/ {print $2}')

  cat > $TARGET/etc/udev/rules.d/70-persistent-net.rules << EOF
## Generated by Sipwise deployment script
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}==$INT_MAC, ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="$INTERNAL_DEV"
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}==$EXT_MAC, ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="$EXTERNAL_DEV"
EOF
fi

if "$NGCP_INSTALLER" ; then

  # add sipwise user
  chroot $TARGET adduser sipwise --disabled-login --gecos "Sipwise"
  echo "sipwise:sipwise" | chroot $TARGET chpasswd

  # default: use latest ngcp-installer
  INSTALLER_PATH=
  INSTALLER=ngcp-installer-latest.deb
  if $LINUX_HA3 ; then
    INSTALLER=ngcp-installer-ha-v3-latest.deb
  fi

  # use specific SP/CE version and installer version if specified
  if [ -n "$SP_VERSION" ] && [ -n "$INSTALLER_VERSION" ] ; then
    INSTALLER_PATH=$SP_VERSION/pool/main/n/ngcp-installer/
    if $PRO_EDITION && ! $LINUX_HA3 ; then # HA v2
      INSTALLER=ngcp-installer-pro_${INSTALLER_VERSION}_all.deb
    elif $PRO_EDITION && $LINUX_HA3 ; then # HA v3
      INSTALLER=ngcp-installer-pro-ha-v3_${INSTALLER_VERSION}_all.deb
    else # spce
      INSTALLER=ngcp-installer-ce_${INSTALLER_VERSION}_all.deb
    fi
  fi

  if $PRO_EDITION ; then
    INSTALLER_PATH="http://deb.sipwise.com/sppro/$INSTALLER_PATH"
  else
    INSTALLER_PATH="http://deb.sipwise.com/spce/$INSTALLER_PATH"
  fi

  # ngcp-installer from trunk or a release build
  if [ "$INSTALLER_VERSION" = "trunk" ] || $TRUNK_VERSION || [ -n "$AUTOBUILD_RELEASE" ] ; then
    INSTALLER_PATH='http://deb.sipwise.com/autobuild/debian/pool/main/n/ngcp-installer/'

    wget --directory-prefix=debs --no-directories -r --no-parent "$INSTALLER_PATH"
    VERSION=$(dpkg-scanpackages debs /dev/null 2>/dev/null | awk '/Version/ {print $2}' | sort -ur)

    [ -n "$VERSION" ] || { echo "Error: installer version could not be detected." >&2 ; exit 1 ; }

    if $PRO_EDITION ; then
      INSTALLER="ngcp-installer-pro_${VERSION}_all.deb"
    else
      INSTALLER="ngcp-installer-ce_${VERSION}_all.deb"
    fi
  fi

  # support testing rc releases without providing an according installer package ahead
  if [ -n "$AUTOBUILD_RELEASE" ] ; then
    echo "Running installer with sources.list for $DEBIAN_RELEASE + autobuild release-$AUTOBUILD_RELEASE"

    cat > $TARGET/etc/apt/sources.list << EOF
## custom sources.list, deployed via deployment.sh

# Debian repositories
deb http://ftp.de.debian.org/debian/ ${DEBIAN_RELEASE} main
deb http://security.debian.org/ ${DEBIAN_RELEASE}/updates main
deb http://ftp.debian.org/debian ${DEBIAN_RELEASE}-updates main

# Sipwise repositories
deb http://deb.sipwise.com/autobuild/release/release-${AUTOBUILD_RELEASE} release-${AUTOBUILD_RELEASE} main

# Sipwise ${DEBIAN_RELEASE} backports
deb http://deb.sipwise.com/${DEBIAN_RELEASE}-backports/ ${DEBIAN_RELEASE}-backports main

# Percona's high performance mysql builds
deb http://deb.sipwise.com/percona/ ${DEBIAN_RELEASE} main

# Sipdoc.net repository for misc voip tools
deb http://deb.sipdoc.net debian main
EOF
  fi

  # install and execute ngcp-installer
  if $PRO_EDITION && ! $LINUX_HA3 ; then # HA v2
    cat << EOT | grml-chroot $TARGET /bin/bash
wget ${INSTALLER_PATH}/${INSTALLER}
dpkg -i $INSTALLER
TRUNK_VERSION=$TRUNK_VERSION SKIP_SOURCES_LIST=$SKIP_SOURCES_LIST ngcp-installer \$ROLE \$IP1 \$IP2 \$EADDR \$EIFACE 2>&1 | tee -a /tmp/ngcp-installer-debug.log
RC=\${PIPESTATUS[0]}
if [ \$RC -ne 0 ] ; then
  echo "Fatal error while running ngcp-installer:" >&2
  tail -10 /tmp/ngcp-installer.log
  exit \$RC
fi
EOT

  elif $PRO_EDITION && $LINUX_HA3 ; then # HA v3
    cat << EOT | grml-chroot $TARGET /bin/bash
wget ${INSTALLER_PATH}/${INSTALLER}
dpkg -i $INSTALLER
TRUNK_VERSION=$TRUNK_VERSION SKIP_SOURCES_LIST=$SKIP_SOURCES_LIST ngcp-installer \$ROLE \$IP1 \$IP2 \$EADDR \$EIFACE \$MCASTADDR 2>&1 | tee -a /tmp/ngcp-installer-debug.log
RC=\${PIPESTATUS[0]}
if [ \$RC -ne 0 ] ; then
  echo "Fatal error while running ngcp-installer (HA v3):" >&2
  tail -10 /tmp/ngcp-installer.log
  exit \$RC
fi
EOT

  else # spce
    cat << EOT | grml-chroot $TARGET /bin/bash
wget ${INSTALLER_PATH}/${INSTALLER}
dpkg -i $INSTALLER
echo y | TRUNK_VERSION=$TRUNK_VERSION SKIP_SOURCES_LIST=$SKIP_SOURCES_LIST ngcp-installer 2>&1 | tee -a /tmp/ngcp-installer-debug.log
RC=\${PIPESTATUS[1]}
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
    echo "         $TARGET/tmp/ngcp-installer-debug.log" >&2
    exit 1
  fi

  # we require those packages for dkms, so do NOT remove them:
  # binutils cpp-4.3 gcc-4.3-base linux-kbuild-2.6.32
  if chroot $TARGET dkms status | grep -q ngcp-mediaproxy-ng ; then
    if chroot $TARGET dkms status | grep -q '^ngcp-mediaproxy-ng.*: installed' ; then
      echo "ngcp-mediaproxy-ng. kernel package already installed, skipping"
    else
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
  fi

  # make sure all services are stopped
  for service in \
    apache2 \
    asterisk \
    collectd \
    exim4 \
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

  # make a backup of the installer logfiles for later investigation
  if [ -r "${TARGET}"/tmp/ngcp-installer.log ] ; then
    cp "${TARGET}"/tmp/ngcp-installer.log "${TARGET}"/var/log/
  fi
  if [ -r "${TARGET}"/tmp/ngcp-installer-debug.log ] ; then
    cp "${TARGET}"/tmp/ngcp-installer-debug.log "${TARGET}"/var/log/
  fi
  if [ -r /tmp/grml-debootstrap.log ] ; then
    cp /tmp/grml-debootstrap.log "${TARGET}"/var/log/
  fi

  echo "# deployment.sh running on $(date)" > "${TARGET}"/var/log/deployment.log
  echo "SCRIPT_VERSION=${SCRIPT_VERSION}" >> "${TARGET}"/var/log/deployment.log
  echo "CMD_LINE=\"${CMD_LINE}\"" >> "${TARGET}"/var/log/deployment.log

fi

# leave system in according state
cat > $TARGET/etc/hostname << EOF
${TARGET_HOSTNAME}
EOF

if "$DHCP" ; then
  cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug $EXTERNAL_DEV
iface $EXTERNAL_DEV inet dhcp
EOF
  # make sure internal network is available even with external
  # device using DHCP
  if "$PRO_EDITION" ; then
  cat >> $TARGET/etc/network/interfaces << EOF

auto $INTERNAL_DEV
iface $INTERNAL_DEV inet static
        address $INTERNAL_IP
        netmask $INTERNAL_NETMASK

EOF
  fi
else
  # assume host system has a valid configuration
  if "$PRO_EDITION" && "$BONDING" ; then
    cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

auto $EXTERNAL_DEV
iface $EXTERNAL_DEV inet static
        address $(ifdata -pa $EXTERNAL_DEV)
        netmask $(ifdata -pn $EXTERNAL_DEV)
        gateway $(route -n | awk '/^0\.0\.0\.0/{print $2; exit}')
        dns-nameservers $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | xargs echo -n)
        bond-slaves $EXTERNAL_DEV $INTERNAL_DEV
        bond_mode 802.3ad
        bond_miimon 100
        bond_lacp_rate 1

auto $INTERNAL_DEV
iface $INTERNAL_DEV inet static
        address $INTERNAL_IP
        netmask $INTERNAL_NETMASK

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
  elif "$PRO_EDITION" ; then # no bonding but pro-edition
    cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

auto $EXTERNAL_DEV
iface $EXTERNAL_DEV inet static
        address $(ifdata -pa $EXTERNAL_DEV)
        netmask $(ifdata -pn $EXTERNAL_DEV)
        gateway $(route -n | awk '/^0\.0\.0\.0/{print $2; exit}')
        dns-nameservers $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | xargs echo -n)

auto $INTERNAL_DEV
iface $INTERNAL_DEV inet static
        address $INTERNAL_IP
        netmask $INTERNAL_NETMASK

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
  else # ce edition
    cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

auto $EXTERNAL_DEV
iface $EXTERNAL_DEV inet static
        address $(ifdata -pa $EXTERNAL_DEV)
        netmask $(ifdata -pn $EXTERNAL_DEV)
        gateway $(route -n | awk '/^0\.0\.0\.0/{print $2; exit}')
        dns-nameservers $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | xargs echo -n)

### Further usage examples

## Enable IPv6 autoconfiguration:
# auto eth1
# iface eth1 inet6 manual
#  up ifconfig eth1 up

## Specific manual configuration:
# allow-hotplug eth2
# iface eth2 inet static
#         address 192.168.1.101
#         netmask 255.255.255.0
#         network 192.168.1.0
#         broadcast 192.168.1.255
#         gateway 192.168.1.1
#         # dns-* options are implemented by the resolvconf package, if installed
#         dns-nameservers 195.58.160.194 195.58.161.122
#         dns-search sipwise.com
EOF
  fi
fi # if $DHCP

# finalise hostname configuration
cat > $TARGET/etc/hosts << EOF
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

EOF

# append hostnames of sp1/sp2 so they can talk to each other
# in the HA setup
if "$PRO_EDITION" ; then
  cat >> $TARGET/etc/hosts << EOF
$IP1 sp1
$IP2 sp2
EOF
else
  # otherwise 'hostname --fqdn' does not work and causes delays with exim4 startup
  cat >> $TARGET/etc/hosts << EOF
# required for FQDN, please adjust if needed
127.0.0.1 $TARGET_HOSTNAME
EOF
fi

if [ -n "$PUPPET" ] ; then
  chroot $TARGET sed -i 's/START=.*/START=yes/' /etc/default/puppet

  cat >> ${TARGET}/etc/puppet/puppet.conf << EOF
server=puppet.mgm.sipwise.com
certname=$TARGET_HOSTNAME

[agent]
environment = $PUPPET
EOF

  grml-chroot $TARGET puppet agent --test --waitforcert 30 --fqdn ${TARGET_HOSTNAME} || true
fi

# make sure we don't leave any running processes
for i in asterisk atd collectd collectdmon dbus-daemon exim4 \
         glusterfs glusterfsd haveged nscd   \
	 redis-server snmpd ; do
  killall -9 $i >/dev/null 2>&1 || true
done

upload_db_dump() {
  chroot $TARGET /etc/init.d/mysql restart || true

  # retrieve list of databases
  databases=$(chroot $TARGET mysql -B -N -e 'show databases' | grep -ve '^information_schema$' -ve '^mysql$')

  if [ -z "$databases" ] ; then
    echo "Warning: could not retrieve list of available databases, retrying in 10 seconds."
    sleep 10
    databases=$(chroot $TARGET mysql -B -N -e 'show databases' | grep -ve '^information_schema$' -ve '^mysql$')

    if [ -z "$databases" ] ; then
      echo "Warning: still could not retrieve list of available databases, giving up."
      return 0
    fi
  fi

  if ! chroot $TARGET mysqldump --add-drop-database --no-data -B $databases > /dump.db ; then
    echo "Error while dumping mysql databases." >&2
    exit 1
  fi

  chroot $TARGET /etc/init.d/mysql stop >/dev/null 2>&1 || true

  # mysqldump writes errors to stdout, muhaha...
  if grep -q '^Usage: mysqldump ' /dump.db ; then
    echo "Error: invalid data inside database dump."
    exit 1
  fi

  # upload database dump
  DB_MD5=$(curl --max-time 30 --connect-timeout 30 -F file=@/dump.db http://jenkins.mgm.sipwise.com:4567/upload)

  if [[ "$DB_MD5" == $(md5sum /dump.db | awk '{print $1}') ]] ; then
    echo "Upload of database dump went fine."
  else
    echo '#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!'
    echo '#!#!#!#!#!#!#!      Warning: error while uploading database.      #!#!#!#!#!#!#!'
    echo '#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!'
  fi
}

# upload db dump only if we're deploying a trunk version
if $TRUNK_VERSION ; then
  echo "Trunk version detected, uploading DB dump."
  upload_db_dump
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

# make sure /etc/fstab is up2date
blockdev --rereadpt /dev/$DISK || true

# party time! who brings the whiskey?
echo "Installation finished. \o/"
echo
echo

[ -n "$start_seconds" ] && SECONDS="$[$(cut -d . -f 1 /proc/uptime)-$start_seconds]" || SECONDS="unknown"
echo "Successfully finished deployment process [$(date) - running ${SECONDS} seconds]"

# do not prompt when running inside kantan
if "$KANTAN" ; then
  if [[ "$SHLVL" == "2" ]] || [ -n "${NETSCRIPT:-}" ] ; then
    echo "finished deployment process at $(date)" | telnet 10.0.2.2 8888 || true
    echo "it took ${SECONDS} seconds" | telnet 10.0.2.2 8888 || true
  fi

  # if booting via ngcphalt then just system off...
  if "$HALT" ; then
    echo "Triggering sync and unmounted as requested" | telnet 10.0.2.2 8888 || true
    for key in s u ; do
      echo $key > /proc/sysrq-trigger
      sleep 2
    done
  fi

  echo "Terminating Kantan deployment process now."
  echo kantan_terminate | telnet 10.0.2.2 8888 || true
  exit 0
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
