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
VLAN=false
RETRIEVE_MGMT_CONFIG=false
LINUX_HA3=false
TRUNK_VERSION=false
DEBIAN_RELEASE=squeeze
KANTAN=false
HALT=false
REBOOT=false
STATUS_DIRECTORY=/srv/deployment/
STATUS_WAIT=0

if [ -L /sys/block/vda ] ; then
  export DISK=vda # will be configured as /dev/vda
else
  export DISK=sda # will be configured as /dev/sda
fi


### helper functions {{{
set_deploy_status() {
  [ -n "$1" ] || return 1
  echo "$*" > "${STATUS_DIRECTORY}"/status
}

enable_deploy_status_server() {
  mkdir -p "${STATUS_DIRECTORY}"

  # get rid of already running process
  PID=$(pgrep -f 'python.*SimpleHTTPServer') || true
  [ -n "$PID" ] && kill $PID

  (
    cd "${STATUS_DIRECTORY}"
    python -m SimpleHTTPServer 4242 &
  )
}

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

Install ngcp: $NGCP_INSTALLER | Install pro: $PRO_EDITION [$ROLE] | Install ce: $CE_EDITION
Installing $SP_VERSION_STR platform using installer version $INSTALLER_VERSION_STR
Install IP: $INSTALL_IP | Started deployment at $(date)

EOF
}
### }}}

# logging {{{
cat > /etc/rsyslog.d/logsend.conf << EOF
*.*  @@192.168.51.28
EOF
/etc/init.d/rsyslog restart

logit() {
  logger -t grml-deployment "$@"
}

die() {
  logger -t grml-deployment "$@"
  echo "$@" >&2
  exit 1
}

logit "host-IP: $(ip-screen)"
logit "deployment-version: $SCRIPT_VERSION"
# }}}

enable_deploy_status_server

set_deploy_status "checkBootParam"

if checkBootParam debugmode ; then
  set -x
  PS4='+\t '
fi

if checkBootParam ngcpstatus ; then
  STATUS_WAIT=$(getBootParam ngcpstatus || true)
  [ -n "$STATUS_WAIT" ] || STATUS_WAIT=30
fi

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

if checkBootParam ngcpvlan ; then
  VLAN=true
fi

if checkBootParam ngcpmgmt ; then
  MANAGEMENT_IP=$(getBootParam ngcpmgmt)
  RETRIEVE_MGMT_CONFIG=true
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

if checkBootParam "debianrelease" ; then
  DEBIAN_RELEASE=$(getBootParam debianrelease)
fi

ARCH=$(dpkg --print-architecture)
if checkBootParam "arch" ; then
  ARCH=$(getBootParam arch)
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
    die "Error: No argument for ngcpprofile found, can not continue."
  fi
fi

if checkBootParam kantan ; then
  KANTAN=true
fi

if checkBootParam ngcphalt ; then
  HALT=true
fi

if checkBootParam ngcpreboot ; then
  REBOOT=true
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
    *ngcpreboot*) REBOOT=true;;
  esac
  shift
done

if ! "$NGCP_INSTALLER" ; then
  PRO_EDITION=false
  CE_EDITION=false
  unset ROLE
fi

set_deploy_status "getconfig"

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
      rm -rf $DOWNLOADDIR/*
      rmdir -p $DOWNLOADDIR
      die "Error: No default.sh in profile $PROFILE from $NETSCRIPT_SERVER"
    fi
  else
    die "Error: Could not get profile $PROFILE from $NETSCRIPT_SERVER"
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
    2.5) INSTALLER_VERSION="0.7.3";;
    2.6-rc1) INSTALLER_VERSION="0.8.1";;
    2.6-rc2) INSTALLER_VERSION="0.8.2";;
    2.6) INSTALLER_VERSION="0.8.3";;
  esac
elif "$CE_EDITION" ; then
  case "$SP_VERSION" in
    # we do not have a local mirror for lenny, so disable it
    2.1) INSTALLER_VERSION="0.3.2" ; DEBIAN_RELEASE="lenny" ;;
    2.2) INSTALLER_VERSION="0.4.7";;
    2.4) INSTALLER_VERSION="0.6.3";;
    2.5) INSTALLER_VERSION="0.7.3";;
    2.6-rc1) INSTALLER_VERSION="0.8.1";;
    2.6-rc2) INSTALLER_VERSION="0.8.2";;
    2.6) INSTALLER_VERSION="0.8.3";;
  esac
fi

set_deploy_status "settings"

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

set_deploy_status "start"

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
     die "Error: no $INTERNAL_DEV NIC found, can not deploy internal network. Exiting."
   fi

  # ipmi on IBM hardware
  if ifconfig usb0 &>/dev/null ; then
    ifconfig usb0 169.254.1.102 netmask 255.255.0.0
  fi
fi

set_deploy_status "diskverify"

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

  # PERC H700, PERC H710,...
  if grep -q 'PERC' /sys/block/${DISK}/device/model && \
    grep -q "DELL" /sys/block/${DISK}/device/vendor ; then
    return 0
  fi

  # no match so far?
  return 1
}

# run in according environment only
if [[ $(imvirt 2>/dev/null) == "Physical" ]] ; then

  if ! check_for_supported_disk ; then
    die "Error: /dev/${DISK} does not look like a VirtIO, ServeRAID, LSILOGIC or PowerEdge disk/controller. Exiting to avoid possible data damage."
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
    die "Error: /dev/${DISK} does not look like a virtual disk. Exiting to avoid possible data damage. Note: imvirt output is $(imvirt)"
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
set_deploy_status "disksetup"

# 2000GB = 2097152000 blocks in /proc/partitions - so make a rough estimation
if [ $(awk "/ ${DISK}$/ {print \$3}" /proc/partitions) -gt 2000000000 ] ; then
  TABLE=gpt
else
  TABLE=msdos
fi
parted -s /dev/${DISK} mktable "$TABLE"
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

set_deploy_status "debootstrap"

# install Debian
echo y | grml-debootstrap \
  --arch "${ARCH}" \
  --grub /dev/${DISK} \
  --hostname "${TARGET_HOSTNAME}" \
  --mirror "$MIRROR" \
  --debopt '--no-check-gpg' $EXTRA_DEBOOTSTRAP_OPTS \
  -r "$DEBIAN_RELEASE" \
  -t "/dev/${DISK}1" \
  --password 'sipwise' 2>&1 | tee -a /tmp/grml-debootstrap.log

if [ ${PIPESTATUS[1]} -ne 0 ]; then
  die "Error during installation of Debian ${DEBIAN_RELEASE}. Find details via: mount /dev/${DISK}1 $TARGET ; ls $TARGET/debootstrap/*.log"
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
ca-certificates openssl tcpd xauth

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

# needed for carrier
if "$RETRIEVE_MGMT_CONFIG" ; then
  echo "Retrieving /etc/hosts configuration from management server"
  wget --timeout=30 -O "$TARGET/etc/hosts" "${MANAGEMENT_IP}:3000/hostconfig/$(cat ${TARGET}/etc/hostname)"
fi

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

  if [ "$INT_MAC" = "$EXT_MAC" ] ; then
    echo "Error: MAC address for $INTERNAL_DEV is same as for $EXTERNAL_DEV" >&2
    exit 1
  fi

  cat > $TARGET/etc/udev/rules.d/70-persistent-net.rules << EOF
## Generated by Sipwise deployment script
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}==$INT_MAC, ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="$INTERNAL_DEV"
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}==$EXT_MAC, ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="$EXTERNAL_DEV"
EOF
fi

# needs to be executed *after* udev rules have been set up,
# otherwise we get duplicated MAC address<->device name mappings
if "$RETRIEVE_MGMT_CONFIG" ; then
  echo "Retrieving network configuration from management server"
  wget --timeout=30 -O /etc/network/interfaces "${MANAGEMENT_IP}:3000/nwconfig/$(cat ${TARGET}/etc/hostname)"

  cp /etc/network/interfaces "${TARGET}/etc/network/interfaces"

  # make sure we can access the management system which might be reachable
  # through a specific VLAN only
  ip link set dev "$INTERNAL_DEV" down # avoid conflicts with VLAN device(s)

  # vlan-raw-device b0 doesn't exist in the live environment, if we don't
  # adjust it accordingly for our environment the vlan device(s) can't be
  # brought up
  # note: we do NOT modify the /e/n/i file from $TARGET here by intention
  sed -i "s/vlan-raw-device .*/vlan-raw-device eth0/" /etc/network/interfaces

  for interface in $(awk '/^auto vlan/ {print $2}' /etc/network/interfaces) ; do
    echo "Bringing up VLAN interface $interface"
    ifup "$interface"
  done
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

    # inside the pool there might be versions which have been released inside a
    # maintenance branch but which don't cover recent changes in trunk,
    # therefore get rid of every file without "svn" in the filename, so e.g.
    #   ngcp-installer-ce_0.7.2+0~1339173026.svn9034.165_all.deb (trunk version)
    # is preferred over
    #   ngcp-installer-ce_0.7.3_all.deb (release into 2.5 repository)
    find ./debs -type f -a ! -name \*svn\* -exec rm {} +

    VERSION=$(dpkg-scanpackages debs /dev/null 2>/dev/null | awk '/Version/ {print $2}' | sort -ur)

    [ -n "$VERSION" ] || die "Error: installer version could not be detected."

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

set_deploy_status "ngcp-installer"

  # install and execute ngcp-installer
  logit "ngcp-installer: $INSTALLER"
  if $PRO_EDITION && ! $LINUX_HA3 ; then # HA v2
    echo "TRUNK_VERSION=$TRUNK_VERSION SKIP_SOURCES_LIST=$SKIP_SOURCES_LIST ngcp-installer $ROLE $IP1 $IP2 $EADDR $EIFACE" > /tmp/ngcp-installer-cmdline.log
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
    echo "TRUNK_VERSION=$TRUNK_VERSION SKIP_SOURCES_LIST=$SKIP_SOURCES_LIST ngcp-installer $ROLE $IP1 $IP2 $EADDR $EIFACE $MCASTADDR" > /tmp/ngcp-installer-cmdline.log
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
    echo "TRUNK_VERSION=$TRUNK_VERSION SKIP_SOURCES_LIST=$SKIP_SOURCES_LIST ngcp-installer" > /tmp/ngcp-installer-cmdline.log
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
  if [ $? -eq 0 ] ; then
    logit "installer: success"
  else
    logit "installer: error"
    die "Error during installation of ngcp. Find details at: $TARGET/tmp/ngcp-installer.log $TARGET/tmp/ngcp-installer-debug.log"
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
         die "Error: no kernel headers found for building the ngcp-mediaproxy-ng kernel module."
      fi
      KERNELVERSION=${KERNELHEADERS##linux-headers-}
      NGCPVERSION=$(chroot $TARGET dkms status | grep ngcp-mediaproxy-ng | awk -F, '{print $2}' | sed 's/:.*//')
      chroot $TARGET dkms build -k $KERNELVERSION --kernelsourcedir /usr/src/$KERNELHEADERS \
             -m ngcp-mediaproxy-ng -v $NGCPVERSION
      chroot $TARGET dkms install -k $KERNELVERSION -m ngcp-mediaproxy-ng -v $NGCPVERSION
    fi
  fi

adjust_hb_device() {
  local hb_device

  if [ -n "$INTERNAL_DEV" ] ; then
    export hb_device="$INTERNAL_DEV"
  else
    export hb_device="eth1" # default
  fi

  echo "Setting hb_device to ${hb_device}."

  chroot $TARGET perl <<"EOF"
use strict;
use warnings;
use YAML::Tiny;
use Env qw(hb_device);

my $yaml = YAML::Tiny->new;
my $inputfile  = '/etc/ngcp-config/config.yml';
my $outputfile = '/etc/ngcp-config/config.yml';

$yaml = YAML::Tiny->read($inputfile);
$yaml->[0]->{networking}->{hb_device} = "$hb_device";
$yaml->write($outputfile);
EOF

  chroot $TARGET ngcpcfg commit 'setting hb_device in config.yml [via deployment process]'
  chroot $TARGET ngcpcfg build /etc/ha.d/ha.cf
}

  if "$PRO_EDITION" ; then
    echo "Deploying PRO edition (sp1) - adjusting heartbeat device (hb_device)."
    adjust_hb_device
  fi

  # make sure all services are stopped
  for service in \
    apache2 \
    asterisk \
    collectd \
    exim4 \
    irqbalance \
    kamailio-lb \
    kamailio-proxy \
    mediator \
    monit \
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
  echo "NGCP_INSTALLER_CMDLINE=\"TRUNK_VERSION=$TRUNK_VERSION SKIP_SOURCES_LIST=$SKIP_SOURCES_LIST ngcp-installer $ROLE $IP1 $IP2 $EADDR $EIFACE $MCASTADDR\"" >> "${TARGET}"/var/log/deployment.log

fi

# adjust network.yml
if "$PRO_EDITION" ; then
  # set variable to have the *other* node from the PRO setup available for ngcp-network
  case $ROLE in
    sp1) PEER=sp2 ;;
    sp2) PEER=sp1 ;;
  esac

  cat << EOT | grml-chroot $TARGET /bin/bash
  if ! [ -r /etc/ngcp-config/network.yml ] ; then
    echo '/etc/ngcp-config/network.yml does not exist'
    exit 0
  fi

  cp /etc/ngcp-config/network.yml /etc/ngcp-config/network.yml.factory_default

  ngcp-network --set-interface=lo --set-interface=$DEFAULT_INSTALL_DEV --set-interface=$INTERNAL_DEV
  ngcp-network --peer=$PEER
  ngcp-network --host=$PEER --peer=$ROLE --set-interface=lo
  ngcp-network --set-interface=$INTERNAL_DEV
  ngcp-network --move-from=lo --move-to=$INTERNAL_DEV --type=ha_int
  ngcp-network --set-interface=eth1 --host=$PEER --ip=$DEFAULT_IP2 --netmask=$DEFAULT_INTERNAL_NETMASK --type=ha_int

  cp /etc/ngcp-config/network.yml /mnt/glusterfs/shared_config/network.yml

  ngcpcfg build
EOT
fi

if "$RETRIEVE_MGMT_CONFIG" ; then
  echo "Nothing to do, /etc/network/interfaces was already set up."
elif "$DHCP" ; then
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
  if "$PRO_EDITION" && "$VLAN" ; then
    cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

auto b0
iface b0 inet static
        address $(ifdata -pa $EXTERNAL_DEV)
        netmask $(ifdata -pn $EXTERNAL_DEV)
        gateway $(route -n | awk '/^0\.0\.0\.0/{print $2; exit}')
        dns-nameservers $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | xargs echo -n)
        bond-slaves $EXTERNAL_DEV $INTERNAL_DEV
        bond_mode 802.3ad
        bond_miimon 100
        bond_lacp_rate 1

auto vlan3
iface vlan3 inet static
        address $(ifdata -pa $INTERNAL_DEV)
        netmask $(ifdata -pn $INTERNAL_DEV)
        vlan-raw-device $EXTERNAL_DEV

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
  elif "$PRO_EDITION" && "$BONDING" ; then
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

generate_etc_hosts() {

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

}

if "$RETRIEVE_MGMT_CONFIG" ; then
  echo "Nothing to do, /etc/hosts was already set up."
else
  echo "Generting /etc/hosts"
  generate_etc_hosts
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
	 redis-server snmpd voisniff-ng ; do
  killall -9 $i >/dev/null 2>&1 || true
done

upload_file() {
  [ -n "$1" ] || return 1

  file="$1"

  DB_MD5=$(curl --max-time 180 --connect-timeout 30 -F file=@"${file}" http://jenkins.mgm.sipwise.com:4567/upload)

  if [[ "$DB_MD5" == $(md5sum "${file}" | awk '{print $1}') ]] ; then
    echo "Upload of $file went fine."
  else
    echo "#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!"
    echo "#!#!#!#!#!#!#!      Warning: error while uploading ${file}.      #!#!#!#!#!#!#!"
    echo "#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!"
  fi
}

upload_db_dump() {
  if "$CE_EDITION" ; then
    echo "CE edition noticed, continuing..."
  else
    echo "This is not a CE edition, ignoring request to generate and upload DB dump."
    return 0
  fi

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

  # the only way to rely on mysqldump writing useful data is checking for "Dump
  # completed on" inside the dump as it writes errors also to stdout, so before
  # actually dumping it for committing it to VCS we need to dump it once without
  # the "--skip-comments" option, do the check on that and then really dump it
  # later...
  if ! chroot $TARGET mysqldump --add-drop-database -B $databases > /dump.db ; then
    die "Error while dumping mysql databases."
  fi

  if ! grep -q 'Dump completed on' /dump.db ; then
    die "Error: invalid data inside database dump."
  fi

  if ! chroot $TARGET mysqldump --add-drop-database --skip-comments -B $databases > /dump.db ; then
    die "Error while dumping mysql databases."
  fi

  chroot $TARGET /etc/init.d/mysql stop >/dev/null 2>&1 || true

  echo
  echo "NOTE: you can safely IGNORE the message stating:"
  echo "        ERROR 2002 (HY000): Can't connect to local MySQL server through socket ..."
  echo "      listed above. If you're seeing this note here everything went fine."
  echo

  upload_file "/dump.db"
}

upload_yml_cfg() {
  if "$CE_EDITION" ; then
    echo "CE edition noticed, continuing..."
  else
    echo "This is not a CE edition, ignoring request to generate and upload  dump."
    return 0
  fi

  cat << EOT | grml-chroot $TARGET /bin/bash
# CE
/usr/share/ngcp-cfg-schema/cfg_scripts/init/0001_init_config_ce.up    /dev/null  /config_ce.yml
/usr/share/ngcp-cfg-schema/cfg_scripts/init/0002_init_constants_ce.up /dev/null  /constants_ce.yml

# PRO
/usr/share/ngcp-cfg-schema/cfg_scripts/init/0001_init_config_pro.up    /dev/null /config_pro.yml
/usr/share/ngcp-cfg-schema/cfg_scripts/init/0002_init_constants_pro.up /dev/null /constants_pro.yml

# config.yml
for file in /usr/share/ngcp-cfg-schema/cfg_scripts/config/*.up ; do
  [ -r \$file ] || continue
  case $(basename \$file) in
    *_pro.up)
      \$file /config_pro.yml /config_pro.yml
      ;;
    *_ce.up)
      \$file /config_ce.yml  /config_ce.yml
      ;;
    *)
      \$file /config_ce.yml  /config_ce.yml
      \$file /config_pro.yml /config_pro.yml
      ;;
  esac
done

# constants.yml
for file in /usr/share/ngcp-cfg-schema/cfg_scripts/constants/*.up ; do
  [ -r \$file ] || continue
  case $(basename \$file) in
    *_pro.up)
      \$file /constants_pro.yml /constants_pro.yml
      ;;
    *_ce.up)
      \$file /constants_ce.yml  /constants_ce.yml
      ;;
    *)
      \$file /constants_ce.yml  /constants_ce.yml
      \$file /constants_pro.yml /constants_pro.yml
      ;;
  esac
done
EOT

  for file in config_ce.yml constants_ce.yml config_pro.yml constants_pro.yml ; do
    upload_file "${TARGET}/$file"
  done
}

# upload db dump only if we're deploying a trunk version
if $TRUNK_VERSION && ! checkBootParam ngcpnoupload ; then
  set_deploy_status "upload_data"
  echo "Trunk version detected, considering DB dump upload."
  upload_db_dump
  echo "Trunk version detected, considering yml configs upload."
  upload_yml_cfg
fi

# remove retrieved and generated files
rm -f ${TARGET}/config_*yml
rm -f ${TARGET}/constants_*.yml
rm -f ${TARGET}/ngcp-installer*deb

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
if ! blockdev --rereadpt /dev/$DISK ; then
  echo "Something on disk /dev/$DISK (mountpoint $TARGET) seems to be still active, debugging output follows:"
  ps auxwww || true
fi

# party time! who brings the whiskey?
echo "Installation finished. \o/"
echo
echo

[ -n "$start_seconds" ] && SECONDS="$[$(cut -d . -f 1 /proc/uptime)-$start_seconds]" || SECONDS="unknown"
logit "Successfully finished deployment process [$(date) - running ${SECONDS} seconds]"
echo "Successfully finished deployment process [$(date) - running ${SECONDS} seconds]"

if "$KANTAN" ; then
  if [[ "$SHLVL" == "2" ]] || [ -n "${NETSCRIPT:-}" ] ; then
    echo "finished deployment process at $(date)" | telnet 10.0.2.2 8888 || true
    echo "it took ${SECONDS} seconds" | telnet 10.0.2.2 8888 || true
  fi
fi

set_deploy_status "finished"

# if ngcpstatus boot option is used wait for a specific so a
# remote host has a chance to check for deploy status "finished",
# defaults to 0 seconds otherwise
sleep "$STATUS_WAIT"

# do not prompt when running in automated mode
if "$REBOOT" ; then
  echo "Rebooting system as requested via ngcpreboot"
  for key in s u b ; do
    echo $key > /proc/sysrq-trigger
    sleep 2
  done
fi

if "$HALT" ; then
  echo "Halting system as requested via ngcphalt"

  if "$KANTAN" ; then
    echo "Triggering sync and unmount as requested" | telnet 10.0.2.2 8888 || true
  fi

  for key in s u ; do
    echo $key > /proc/sysrq-trigger
    sleep 2
  done
fi

if "$KANTAN" ; then
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
