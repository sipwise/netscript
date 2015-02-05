#!/bin/bash
# Purpose: automatically install Debian + sip:provider platform
################################################################################

INSTALL_LOG='/tmp/deployment-installer-debug.log'
exec  > >(tee -a $INSTALL_LOG    )
exec 2> >(tee -a $INSTALL_LOG >&2)

# set version to git commit ID
SCRIPT_VERSION="%SCRIPT_VERSION%"

# not set? then fall back to timestamp of execution
if [ -z "$SCRIPT_VERSION" ] || [ "$SCRIPT_VERSION" = '%SCRIPT_VERSION%' ] ; then
  SCRIPT_VERSION=$(date +%s) # seconds since 1970-01-01 00:00:00 UTC
fi

# Never ever execute the script outside of a
# running Grml live system because partitioning
# disks might destroy data. Seriously.
if ! [ -r /etc/grml_cd ] ; then
  echo "Not running inside Grml, better safe than sorry. Sorry." >&2
  exit 1
fi

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
CARRIER_EDITION=false
NGCP_INSTALLER=false
PUPPET=''
RESTART_NETWORK=true
INTERACTIVE=false
DHCP=false
LOGO=true
BONDING=false
VLAN=false
VLANID=''
VLANIF=''
RETRIEVE_MGMT_CONFIG=false
LINUX_HA3=false
TRUNK_VERSION=false
DEBIAN_RELEASE=wheezy
HALT=false
REBOOT=false
STATUS_DIRECTORY=/srv/deployment/
STATUS_WAIT=0
LVM=true
VAGRANT=false
ADJUST_FOR_LOW_PERFORMANCE=false
ENABLE_VM_SERVICES=false
FILESYSTEM="ext4"
DEBIAN_REPO_HOST="debian.sipwise.com"
SIPWISE_REPO_HOST="deb.sipwise.com"
SIPWISE_REPO_TRANSPORT="http"
DPL_MYSQL_REPLICATION=true
GRML_PXE_IMAGES_PATH="/lib/live/mount/medium"
PXE_IMAGES_PATH="/tmp/grml_pxe"

# if TARGET_DISK environment variable is set accept it
if [ -n "$TARGET_DISK" ] ; then
  export DISK="${TARGET_DISK}"
else # otherwise try to find sane default
  if [ -L /sys/block/vda ] ; then
    export DISK=vda # will be configured as /dev/vda
  else
    # in some cases, sda is not the HDD, but the CDROM,
    # so better walk through all devices.
    for i in /sys/block/sd*; do
      if grep -q 0 ${i}/removable; then
        export DISK=$(basename $i)
        break
      fi
    done
  fi
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
    python -m SimpleHTTPServer 4242 >/tmp/status_server.log 2>&1 &
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
  for i in $2 ; do
    eval $1[${ind[n++]}]=$i
  done
  [ "$n" == "7" ] && return 0 || return 1
}

install_sipwise_key() {
  if "$PRO_EDITION" ; then
    wget -O /etc/apt/trusted.gpg.d/sipwise.gpg http://${SIPWISE_REPO_HOST}/sppro/sipwise.gpg
  else
    wget -O /etc/apt/trusted.gpg.d/sipwise.gpg http://${SIPWISE_REPO_HOST}/spce/sipwise.gpg
  fi

  md5sum_sipwise_key_expected=32a4907a7d7aabe325395ca07c531234
  md5sum_sipwise_key_calculated=$(md5sum /etc/apt/trusted.gpg.d/sipwise.gpg | awk '{print $1}')

  if [ "$md5sum_sipwise_key_calculated" != "$md5sum_sipwise_key_expected" ] ; then
    die "Error validating sipwise keyring for apt usage (expected: [$md5sum_sipwise_key_expected] - got: [$md5sum_sipwise_key_calculated])"
  fi
}

# see MT#6253
fai_upgrade() {
  upgrade=false # upgrade only if needed

  local required_version=4.2.4+0
  local present_version=$(dpkg-query --show --showformat='${Version}' fai-setup-storage)

  if dpkg --compare-versions $present_version lt $required_version ; then
    echo "fai-setup-storage version $present_version is older than minimum required version $required_version - upgrading."
    upgrade=true
  fi

  local required_version=0.17-2
  local present_version=$(dpkg-query --show --showformat='${Version}' liblinux-lvm-perl)

  if dpkg --compare-versions $present_version lt $required_version ; then
    echo "liblinux-lvm-perl version $present_version is older than minimum required version $required_version - upgrading."
    upgrade=true
  fi

  if ! "$upgrade" ; then
    echo "fai-setup-storage and liblinux-lvm-perl are OK already, nothing to do about it."
    return 0
  fi

  install_sipwise_key

  # use temporary apt database for speed reasons
  local TMPDIR=$(mktemp -d)
  mkdir -p "${TMPDIR}/statedir/lists/partial" "${TMPDIR}/cachedir/archives/partial"
  local debsrcfile=$(mktemp)
  echo "deb http://${SIPWISE_REPO_HOST}/wheezy-backports wheezy-backports main" >> "$debsrcfile"

  DEBIAN_FRONTEND='noninteractive' apt-get -o dir::cache="${TMPDIR}/cachedir" \
    -o dir::state="${TMPDIR}/statedir" -o dir::etc::sourcelist="$debsrcfile" \
    -o Dir::Etc::sourceparts=/dev/null update

  DEBIAN_FRONTEND='noninteractive' apt-get -o dir::cache="${TMPDIR}/cachedir" \
    -o dir::state="${TMPDIR}/statedir" -o dir::etc::sourcelist="$debsrcfile" \
    -o Dir::Etc::sourceparts=/dev/null -y install fai-setup-storage liblinux-lvm-perl
}

grml_debootstrap_upgrade() {
  local required_version=0.67
  local present_version=$(dpkg-query --show --showformat='${Version}' grml-debootstrap)

  if dpkg --compare-versions $present_version lt $required_version ; then
    echo "grml-deboostrap version $present_version is older than minimum required version $required_version - upgrading."

    # use temporary apt database for speed reasons
    local TMPDIR=$(mktemp -d)
    mkdir -p "${TMPDIR}/statedir/lists/partial" "${TMPDIR}/cachedir/archives/partial"
    local debsrcfile=$(mktemp)
    echo "deb http://${SIPWISE_REPO_HOST}/grml.org grml-testing main" >> "$debsrcfile"

    # the Sipwise deb.grml.org mirror is signed with 0xA42C4F2A (= 680FBA8A)
    wget -O /etc/apt/680FBA8A.asc http://${SIPWISE_REPO_HOST}/autobuild/680FBA8A.asc
    apt-key add /etc/apt/680FBA8A.asc

    DEBIAN_FRONTEND='noninteractive' apt-get -o dir::cache="${TMPDIR}/cachedir" \
      -o dir::state="${TMPDIR}/statedir" -o dir::etc::sourcelist="$debsrcfile" \
      -o Dir::Etc::sourceparts=/dev/null update

    DEBIAN_FRONTEND='noninteractive' apt-get -o dir::cache="${TMPDIR}/cachedir" \
      -o dir::state="${TMPDIR}/statedir" -o dir::etc::sourcelist="$debsrcfile" \
      -o Dir::Etc::sourceparts=/dev/null -y install grml-debootstrap
  fi
}

# we need version >=4.3.14-1~bpo70+1 for usage with recent kernel versions
install_vbox_package() {
  echo "Installing virtualbox-guest-additions-iso"

  # use temporary apt database for speed reasons
  local TMPDIR=$(mktemp -d)
  mkdir -p "${TMPDIR}/etc/preferences.d" "${TMPDIR}/statedir/lists/partial" \
    "${TMPDIR}/cachedir/archives/partial"
  echo "deb http://${DEBIAN_REPO_HOST}/debian/ wheezy-backports non-free" > \
    "${TMPDIR}/etc/sources.list"

  DEBIAN_FRONTEND='noninteractive' apt-get -o dir::cache="${TMPDIR}/cachedir" \
    -o dir::state="${TMPDIR}/statedir" -o dir::etc="${TMPDIR}/etc" \
    -o dir::etc::trustedparts="/etc/apt/trusted.gpg.d/" update

  DEBIAN_FRONTEND='noninteractive' apt-get -o dir::cache="${TMPDIR}/cachedir" \
    -o dir::etc="${TMPDIR}/etc" -o dir::state="${TMPDIR}/statedir" \
    -o dir::etc::trustedparts="/etc/apt/trusted.gpg.d/" \
    -y --no-install-recommends install virtualbox-guest-additions-iso
}

ensure_augtool_present() {
  if [ -x /usr/bin/augtool ] ; then
    echo "/usr/bin/augtool is present, nothing to do"
    return 0
  fi
  echo "augtool isn't present, installing augeas-tools package:"

  local TMPDIR=$(mktemp -d)
  mkdir -p "${TMPDIR}/etc/preferences.d" "${TMPDIR}/statedir/lists/partial" \
    "${TMPDIR}/cachedir/archives/partial"
  echo "deb http://${DEBIAN_REPO_HOST}/debian/ wheezy main" > \
    "${TMPDIR}/etc/sources.list"

  DEBIAN_FRONTEND='noninteractive' apt-get -o dir::cache="${TMPDIR}/cachedir" \
    -o dir::state="${TMPDIR}/statedir" -o dir::etc="${TMPDIR}/etc" \
    -o dir::etc::trustedparts="/etc/apt/trusted.gpg.d/" update

  DEBIAN_FRONTEND='noninteractive' apt-get -o dir::cache="${TMPDIR}/cachedir" \
    -o dir::etc="${TMPDIR}/etc" -o dir::state="${TMPDIR}/statedir" \
    -o dir::etc::trustedparts="/etc/apt/trusted.gpg.d/" \
    -y --no-install-recommends install augeas-tools
}
### }}}

# logging {{{
#cat > /etc/rsyslog.d/logsend.conf << EOF
#*.*  @@192.168.51.28
#EOF
#/etc/init.d/rsyslog restart

logit() {
  logger -t grml-deployment "$@"
}

die() {
  logger -t grml-deployment "$@"
  echo "$@" >&2
  set_deploy_status "error"
  exit 1
}

enable_trace() {
  if checkBootParam debugmode ; then
    set -x
    PS4='+\t '
  fi
}

disable_trace() {
  if checkBootParam debugmode ; then
    set +x
    PS4=''
  fi
}


logit "host-IP: $(ip-screen)"
logit "deployment-version: $SCRIPT_VERSION"
# }}}

test -z "${DISK}" \
  && die "Error: No non-removable disk suitable for installation found"

enable_deploy_status_server

set_deploy_status "checkBootParam"

enable_trace

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

if checkBootParam vlan ; then
  VLANPARAMS=($(getBootParam vlan | tr ":" "\n"))
  if [ ${#VLANPARAMS[@]} -eq 2 ] ; then
    VLAN=true
    VLANID=${VLANPARAMS[0]}
    VLANIF=${VLANPARAMS[1]}
  fi
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
CHASSIS="No physical chassis found"
if dmidecode| grep -q 'Rack Mount Chassis' ; then
  CHASSIS="Running in Rack Mounted Chassis."
elif dmidecode| grep -q 'Location In Chassis: Not Specified'; then
  :
elif dmidecode| grep -q 'Location In Chassis'; then
  CHASSIS="Running in blade chassis $(dmidecode| awk '/Location In Chassis/ {print $4}')"
  PRO_EDITION=true
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

if [ -n "$TARGET_HOSTNAME" ] ; then
  export HOSTNAME="$TARGET_HOSTNAME"
else
  [ -n "$HOSTNAME" ] || HOSTNAME="nohostname"
  export HOSTNAME
fi

if checkBootParam ngcpip1 ; then
  IP1=$(getBootParam ngcpip1)
fi

if checkBootParam ngcpip2 ; then
  IP2=$(getBootParam ngcpip2)
fi

if checkBootParam ngcpnetmask ; then
  INTERNAL_NETMASK=$(getBootParam ngcpnetmask)
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
  CARRIER_EDITION=true
fi

if checkBootParam ngcpcmaster ; then
  CMASTER=$(getBootParam ngcpcmaster)
fi

if checkBootParam ngcpnolvm ; then
  logit "Disabling LVM due to ngcpnolvm boot option"
  LVM=false
fi

case "$SP_VERSION" in
  2.*)
    logit "Disabling LVM due to SP_VERSION [$SP_VERSION] matching 2.*"
    LVM=false
    ;;
esac

case "$SP_VERSION" in
  2.*|3.0|3.1|mr3.2*)
    FILESYSTEM="ext3"
    logit "Using filesystem $FILESYSTEM for sip:provider release ${SP_VERSION}"
    ;;
esac

# allow forcing LVM mode
if checkBootParam ngcplvm ; then
  logit "Enabling LVM due to ngcplvm boot option"
  LVM=true
fi

if checkBootParam ngcphalt ; then
  HALT=true
fi

if checkBootParam ngcpreboot ; then
  REBOOT=true
fi

if checkBootParam vagrant ; then
  VAGRANT=true
fi

if checkBootParam lowperformance ; then
  ADJUST_FOR_LOW_PERFORMANCE=true
fi

if checkBootParam enablevmservices ; then
  ENABLE_VM_SERVICES=true
fi

if checkBootParam ngcpnonwrecfg ; then
  logit "Disabling reconfig network as requested via boot option ngcpnonwrecfg"
  RESTART_NETWORK=false
fi

if checkBootParam debianrepo ; then
  DEBIAN_REPO_HOST=$(getBootParam debianrepo)
fi

if checkBootParam sipwiserepo ; then
  SIPWISE_REPO_HOST=$(getBootParam sipwiserepo)
fi

if checkBootParam ngcpnomysqlrepl ; then
  DPL_MYSQL_REPLICATION=false
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
  debianrepo=...   - hostname of Debian APT repository mirror
  sipwiserepo=...  - hostname of Sipwise APT repository mirror
  ngcpnomysqlrepl  - skip MySQL sp1<->sp2 replication configuration/check

Control target system:

  ngcpnw.dhcp      - use DHCP as network configuration in installed system
  ngcphostname=... - hostname of installed system (defaults to ngcp/sp[1,2])
                     NOTE: do NOT use when installing Pro Edition!
  ngcpeiface=...   - external interface device (defaults to eth0)
  ngcpip1=...      - IP address of first node
  ngcpip2=...      - IP address of second node
  ngcpnetmask=...  - netmask of ha_int interface
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
    *ngcphostname=*) TARGET_HOSTNAME=$(echo $param | sed 's/ngcphostname=//');;
    *ngcpeiface=*) EIFACE=$(echo $param | sed 's/ngcpeiface=//');;
    *ngcpeaddr=*) EADDR=$(echo $param | sed 's/ngcpeaddr=//');;
    *ngcpip1=*) IP1=$(echo $param | sed 's/ngcpip1=//');;
    *ngcpip2=*) IP2=$(echo $param | sed 's/ngcpip2=//');;
    *ngcpnetmask=*) INTERNAL_NETMASK=$(echo $param | sed 's/ngcpnetmask=//');;
    *ngcpmcast=*) MCASTADDR=$(echo $param | sed 's/ngcpmcast=//');;
    *ngcpcrole=*) CARRIER_EDITION=true; CROLE=$(echo $param | sed 's/ngcpcrole=//');;
    *ngcpcmaster=*) CMASTER=$(echo $param | sed 's/ngcpcmaster=//');;
    *ngcpnw.dhcp*) DHCP=true;;
    *ngcphav3*) LINUX_HA3=true; PRO_EDITION=true;;
    *ngcpnobonding*) BONDING=false;;
    *ngcpbonding*) BONDING=true;;
    *ngcphalt*) HALT=true;;
    *ngcpreboot*) REBOOT=true;;
    *vagrant*) VAGRANT=true;;
    *lowperformance*) ADJUST_FOR_LOW_PERFORMANCE=true;;
    *enablevmservices*) ENABLE_VM_SERVICES=true;;
  esac
  shift
done

if ! "$NGCP_INSTALLER" ; then
  CARRIER_EDITION=false
  PRO_EDITION=false
  CE_EDITION=false
  unset ROLE
fi

set_deploy_status "grml_debootstrap_upgrade"
grml_debootstrap_upgrade

set_deploy_status "fai_upgrade"
fai_upgrade

if "$NGCP_INSTALLER" ; then
  set_deploy_status "ensure_augtool_present"
  ensure_augtool_present
fi

set_deploy_status "getconfig"

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
logit "INSTALL_IP is $INSTALL_IP"

# if the default network device (eth0) is unconfigured try to retrieve configuration from eth1
if [ "$INSTALL_IP" = "NON-IP" ] && [ "$INSTALL_DEV" = "$DEFAULT_INSTALL_DEV" ] ; then
  logit "Falling back to device eth1 for INSTALL_IP because $DEFAULT_INSTALL_DEV is unconfigured"
  INSTALL_IP="$(ifdata -pa eth1)"
  logit "INSTALL_IP is $INSTALL_IP"
fi

# final external device and IP are same as installation
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

  # needed for carrier
  if "$RETRIEVE_MGMT_CONFIG" ; then
    logit "Retrieving ha_int IPs configuration from management server"
    wget --timeout=30 -O "/tmp/hosts" "${MANAGEMENT_IP}:3000/hostconfig/${TARGET_HOSTNAME}"
    IP1=$(awk '/sp1/ { print $1 }' /tmp/hosts) || IP1=$DEFAULT_IP1
    IP2=$(awk '/sp2/ { print $1 }' /tmp/hosts) || IP2=$DEFAULT_IP2

    if [ -z "$INTERNAL_NETMASK" ]; then
      wget --timeout=30 -O "/tmp/interfaces" "${MANAGEMENT_IP}:3000/nwconfig/${TARGET_HOSTNAME}"
      INTERNAL_NETMASK=$(grep "$INTERNAL_DEV inet" -A2 /tmp/interfaces | awk '/netmask/ { print $2 }')
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

  logit "ha_int sp1: $IP1 sp2: $IP2 netmask: $INTERNAL_NETMASK"
fi

[ -n "$EIFACE" ] || EIFACE=$INSTALL_DEV
[ -n "$EADDR" ] || EADDR=$INSTALL_IP

if "$CE_EDITION" ; then
  case "$SP_VERSION" in
    # we do not have a local mirror for lenny, so disable it
    2.1)     DEBIAN_RELEASE="lenny" ;;
    2.2)     DEBIAN_RELEASE="squeeze" ;;
    2.4)     DEBIAN_RELEASE="squeeze" ;;
    2.5)     DEBIAN_RELEASE="squeeze" ;;
    2.6-rc1) DEBIAN_RELEASE="squeeze" ;;
    2.6-rc2) DEBIAN_RELEASE="squeeze" ;;
    2.6)     DEBIAN_RELEASE="squeeze" ;;
    2.7-rc2) DEBIAN_RELEASE="squeeze" ;;
    2.7-rc3) DEBIAN_RELEASE="squeeze" ;;
    2.7)     DEBIAN_RELEASE="squeeze" ;;
    2.8)     DEBIAN_RELEASE="squeeze" ;;
  esac
fi

set_deploy_status "settings"

### echo settings
[ -n "$SP_VERSION" ] && SP_VERSION_STR=$SP_VERSION || SP_VERSION_STR="<latest>"

echo "Deployment Settings:

  Install ngcp:      $NGCP_INSTALLER"

if "$CE_EDITION" ; then
  echo "  sip:provider:      CE"
elif "$PRO_EDITION" ; then
  echo "  sip:provider:      PRO"
fi

echo "
  Target disk:       /dev/$DISK
  Target Hostname:   $TARGET_HOSTNAME
  Installer version: $SP_VERSION_STR
  Install NW iface:  $INSTALL_DEV
  Install IP:        $INSTALL_IP
  Use DHCP in host:  $DHCP

  Installing in chassis? $CHASSIS

" | tee -a /tmp/installer-settings.txt

if "$PRO_EDITION" ; then
  echo "
  Host Role:         $ROLE
  Host Role Carrier: $CROLE
  Profile:           $PROFILE
  Master Server:     $CMASTER

  External NW iface: $EXTERNAL_DEV
  Ext host IP:       $EXTERNAL_IP
  Ext cluster iface: $EIFACE
  Ext cluster IP:    $EADDR
  Multicast addr:    $MCASTADDR
  Internal NW iface: $INTERNAL_DEV
  Int sp1 host IP:   $IP1
  Int sp2 host IP:   $IP2
  Int netmask:       $INTERNAL_NETMASK
" | tee -a /tmp/installer-settings.txt
fi

if "$INTERACTIVE" ; then
  echo "WARNING: Execution will override any existing data!"
  echo "Settings OK? y/N"
  read a
  if [[ "$a" != "y" ]] ; then
    echo "Exiting as requested."
    exit 2
  fi
  unset a
fi
## }}}

##### all parameters set #######################################################

set_deploy_status "start"

# measure time of installation procedure - everyone loves stats!
start_seconds=$(cut -d . -f 1 /proc/uptime)

if "$LOGO" ; then
  disable_trace
  GRML_INFO=$(cat /etc/grml_version)
  IP_INFO=$(ip-screen)
  CPU_INFO=$(lscpu | awk '/^CPU\(s\)/ {print $2}')
  RAM_INFO=$(/usr/bin/gawk '/MemTotal/{print $2}' /proc/meminfo)
  DATE_INFO=$(date)
  INSTALLER_TYPE="Install CE: $CE_EDITION PRO: $PRO_EDITION [$ROLE] Carrier: $CARRIER_EDITION [$CROLE]"
  # color
  echo -ne "\ec\e[1;32m"
  clear
  #print logo
  echo "+++ Grml-Sipwise Deployment +++"
  echo ""
  echo "$GRML_INFO"
  echo "Host IP(s): $IP_INFO | Deployment version: $SCRIPT_VERSION"
  echo "$CPU_INFO CPU(s) | ${RAM_INFO}kB RAM | $CHASSIS"
  echo ""
  echo "Install ngcp: $NGCP_INSTALLER | $INSTALLER_TYPE"
  echo "Installing $SP_VERSION_STR platform | Debian: $DEBIAN_RELEASE"
  echo "Install IP: $INSTALL_IP | Started deployment at $DATE_INFO"
  # number of lines
  echo -ne "\e[10;0r"
  # reset color
  echo -ne "\e[9B\e[1;m"
  enable_trace
fi

if "$PRO_EDITION" ; then
  if "$RETRIEVE_MGMT_CONFIG" && "$RESTART_NETWORK" ; then
    echo "Skipping $INTERNAL_DEV config"
  else
    # internal network (default on eth1)
    if ifconfig "$INTERNAL_DEV" &>/dev/null ; then
      ifconfig "$INTERNAL_DEV" $INTERNAL_IP netmask $INTERNAL_NETMASK
    else
      die "Error: no $INTERNAL_DEV NIC found, can not deploy internal network. Exiting."
    fi
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

  # IBM System HS23 LSISAS2004
  if grep -q 'Logical Volume' /sys/block/${DISK}/device/model && \
    grep -q "LSI" /sys/block/${DISK}/device/vendor ; then
    return 0
  fi

  # PERC H700, PERC H710,...
  if grep -q 'PERC' /sys/block/${DISK}/device/model && \
    grep -q "DELL" /sys/block/${DISK}/device/vendor ; then
    return 0
  fi

  # proxmox on blade, internal system
  if grep -q 'COMSTAR' /sys/block/${DISK}/device/model && \
    grep -q "OI" /sys/block/${DISK}/device/vendor ; then
    FIRMWARE_PACKAGES="$FIRMWARE_PACKAGES firmware-qlogic"
    return 0
  fi

  # no match so far?
  return 1
}

# run in according environment only
if [ -n "$TARGET_DISK" ] ; then
  logit "Skipping check for supported disk as TARGET_DISK variable is set."
else
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
    elif grep -q 'Virtual disk' /sys/block/${DISK}/device/model && [[ $(imvirt) == "VMware ESX Server" ]] ; then
      echo "Looks like a VMware ESX Server harddisk, ok."
    else
      die "Error: /dev/${DISK} does not look like a virtual disk. Exiting to avoid possible data damage. Note: imvirt output is $(imvirt)"
    fi
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

127.0.0.1 $ROLE $HOSTNAME
$INSTALL_IP $ROLE $HOSTNAME
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

if "$LVM" ; then
  # make sure lvcreate understands the --yes option
  lv_create_opts=''
  lvm_version=$(dpkg-query -W -f='${Version}\n' lvm2)
  if dpkg --compare-versions "$lvm_version" lt 2.02.106 ; then
    logit "Installed lvm2 version ${lvm_version} doesn't need the '--yes' workaround."
  else
    logit "Enabling '--yes' workaround for lvm2 version ${lvm_version}."
    lv_create_opts='lvcreateopts="--yes"'
  fi

  if "$NGCP_INSTALLER" ; then
    VG_NAME="ngcp"
  else
    VG_NAME="vg0"
  fi

  cat > /tmp/partition_setup.txt << EOF
disk_config ${DISK} disklabel:${TABLE} bootable:1
primary -       4096-   -       -

disk_config lvm
vg ${VG_NAME}       ${DISK}1
${VG_NAME}-root     /       -95%      ext3 rw
${VG_NAME}-swap     swap    RAM:50%   swap sw $lv_create_opts
EOF

  # make sure setup-storage doesn't fail if LVM is already present
  dd if=/dev/zero of=/dev/${DISK} bs=1M count=1
  blockdev --rereadpt /dev/${DISK}

  export LOGDIR='/tmp/setup-storage'
  mkdir -p $LOGDIR

  # /usr/lib/fai/fai-disk-info is available as of FAI 4.0,
  # older versions shipped /usr/lib/fai/disk-info which doesn't
  # support the partition setup syntax we use in our setup
  if ! [ -x /usr/lib/fai/fai-disk-info ] ; then
    die "You are using an outdated ISO, please update it to have fai-setup-storage >=4.0.6 available."
  fi

  export disklist=$(/usr/lib/fai/fai-disk-info | sort)
  PATH=/usr/lib/fai:${PATH} setup-storage -f /tmp/partition_setup.txt -X || die "Failure during execution of setup-storage"

  # used later by installer
  ROOT_FS="/dev/mapper/${VG_NAME}-root"
  SWAP_PARTITION="/dev/mapper/${VG_NAME}-swap"

else # no LVM (default)
  parted -s /dev/${DISK} mktable "$TABLE" || die "Failed to set up partition table"
  # hw-raid with rootfs + swap partition
  parted -s /dev/${DISK} 'mkpart primary ext4 2048s 95%' || die "Failed to set up primary partition"
  parted -s /dev/${DISK} 'mkpart primary linux-swap 95% -1' || die "Failed to set up swap partition"
  sync

  # used later by installer
  ROOT_FS="/dev/${DISK}1"
  SWAP_PARTITION="/dev/${DISK}2"

  echo "Initialising swap partition $SWAP_PARTITION"
  mkswap -L ngcp-swap "$SWAP_PARTITION" || die "Failed to initialise swap partition"

  # for later usage in /etc/fstab use /dev/disk/by-label/ngcp-swap instead of /dev/${DISK}2
  SWAP_PARTITION="/dev/disk/by-label/ngcp-swap"
fi

# otherwise e2fsck fails with "need terminal for interactive repairs"
echo FSCK=no >>/etc/debootstrap/config

# package selection
cat > /etc/debootstrap/packages << EOF
# addons: packages which d-i installs but debootstrap doesn't
eject
grub-pc
pciutils
usbutils
ucf
# locales -> but we want locales-all instead:
locales-all

# required e.g. for "Broadcom NetXtreme II BCM5709S Gigabit Ethernet"
# lacking the firmware will result in non-working network on
# too many physical server systems, so just install it by default
firmware-bnx2
firmware-bnx2x

# MT#7999 ethtool used in bonding
ethtool

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

# MT#8813 The linux-headers-2.6-amd64 package doesn't exist in jessie and newer
case "$DEBIAN_RELEASE" in
  lenny|squeeze|wheezy)
    echo  "Adding linux-headers-2.6-amd64 package (because we're installing ${DEBIAN_RELEASE})"
    logit "Adding linux-headers-2.6-amd64 package (because we're installing ${DEBIAN_RELEASE})"
    cat >> /etc/debootstrap/packages << EOF
# required for dkms
linux-headers-2.6-amd64
EOF
    ;;
  *)
    echo  "Adding linux-headers-amd64 package (because we're installing ${DEBIAN_RELEASE})"
    logit "Adding linux-headers-amd64 package (because we're installing ${DEBIAN_RELEASE})"
    cat >> /etc/debootstrap/packages << EOF
# required for dkms
linux-headers-amd64
EOF
    ;;
esac

if "$LVM" ; then
  cat >> /etc/debootstrap/packages << EOF
# support LVM
lvm2
EOF
fi

if "$VLAN" ; then
  cat >> /etc/debootstrap/packages << EOF
# support bridge / bonding / vlan
bridge-utils
ifenslave-2.6
vlan
EOF
fi

if [ -n "$PUPPET" ] ; then
  cat >> /etc/debootstrap/packages << EOF
# for interal use at sipwise
openssh-server
puppet
EOF
fi

if [ -n "$FIRMWARE_PACKAGES" ] ; then
  cat >> /etc/debootstrap/packages << EOF
# firmware packages for hardware specific needs
$FIRMWARE_PACKAGES
EOF
fi

install_sipwise_key

mkdir -p /etc/debootstrap/pre-scripts/
cat > /etc/debootstrap/pre-scripts/install-sipwise-key.sh << EOF
#!/bin/bash
# installed via deployment.sh
cp /etc/apt/trusted.gpg.d/sipwise.gpg "\${MNTPOINT}"/etc/apt/trusted.gpg.d/
EOF
chmod 775 /etc/debootstrap/pre-scripts/install-sipwise-key.sh

# drop this once we mirror Debian/jessie
if [ "$DEBIAN_RELEASE" = "jessie" ] ; then
  MIRROR='http://debian.inode.at/debian/'
  KEYRING='/usr/share/keyrings/debian-archive-keyring.gpg'
else
  # NOTE: we use the debian.sipwise.com CNAME by intention here
  # to avoid conflicts with apt-pinning, preferring deb.sipwise.com
  # over official Debian
  MIRROR="http://${DEBIAN_REPO_HOST}/debian/"
  SEC_MIRROR="http://${DEBIAN_REPO_HOST}/debian-security/"
  KEYRING='/etc/apt/trusted.gpg.d/sipwise.gpg'
fi

set_deploy_status "debootstrap"

mkdir -p /etc/debootstrap/etc/apt/
logit "Setting up /etc/debootstrap/etc/apt/sources.list"
cat > /etc/debootstrap/etc/apt/sources.list << EOF
# Set up via deployment.sh for grml-debootstrap usage
deb ${MIRROR} ${DEBIAN_RELEASE} main contrib non-free
EOF

# drop this once Debian/jessie has security support
if [ -n "$SEC_MIRROR" ] ; then
  echo "deb ${SEC_MIRROR} ${DEBIAN_RELEASE}-security main contrib non-free" >> /etc/debootstrap/etc/apt/sources.list
else
  echo  "Warning: security mirror variable SEC_MIRROR is unset, not enabling security repository for $DEBIAN_RELEASE"
  logit "Warning: security mirror variable SEC_MIRROR is unset, not enabling security repository for $DEBIAN_RELEASE"
fi

echo "deb ${MIRROR} ${DEBIAN_RELEASE}-updates main contrib non-free" >> /etc/debootstrap/etc/apt/sources.list



# install Debian
echo y | grml-debootstrap \
  --arch "${ARCH}" \
  --grub /dev/${DISK} \
  --filesystem "${FILESYSTEM}" \
  --hostname "${TARGET_HOSTNAME}" \
  --mirror "$MIRROR" \
  --debopt "--keyring=${KEYRING}" $EXTRA_DEBOOTSTRAP_OPTS \
  --keep_src_list \
  --defaultinterfaces \
  -r "$DEBIAN_RELEASE" \
  -t "$ROOT_FS" \
  --password 'sipwise' 2>&1 | tee -a /tmp/grml-debootstrap.log

if [ ${PIPESTATUS[1]} -ne 0 ]; then
  die "Error during installation of Debian ${DEBIAN_RELEASE}. Find details via: mount $ROOT_FS $TARGET ; ls $TARGET/debootstrap/*.log"
fi

sync
mount "$ROOT_FS" "$TARGET"

# MT#7805
if "$NGCP_INSTALLER" ; then
  cat << EOT | augtool --root="$TARGET"
insert opt after /files/etc/fstab/*[file="/"]/opt[last()]
set /files/etc/fstab/*[file="/"]/opt[last()] noatime
save
EOT
fi

# provide useable swap partition
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

# make sure `hostname` and `hostname --fqdn` return data from chroot
grml-chroot $TARGET /etc/init.d/hostname.sh

# make sure installations of packages works, will be overriden later again
cat > $TARGET/etc/hosts << EOF
127.0.0.1       localhost
127.0.0.1       $HOSTNAME

::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

# needed for carrier
if "$RETRIEVE_MGMT_CONFIG" ; then
  echo "Retrieving /etc/hosts configuration from management server"
  wget --timeout=30 -O "${TARGET}/etc/hosts" "${MANAGEMENT_IP}:3000/hostconfig/$(cat ${TARGET}/etc/hostname)"
  # required for bootstrapping remote origin in ngcpcfg carrier setup
  echo "Retrieving /etc/ngcp_mgmt_node file from management server"
  wget --timeout=30 -O "${TARGET}/etc/ngcp_mgmt_node" "${MANAGEMENT_IP}:3000/mgmt"
  echo "mgmt_node=$(cat ${TARGET}/etc/ngcp_mgmt_node)"
fi

if "$CARRIER_EDITION" ; then
  echo "Writing $CROLE to /etc/ngcp_ha_role"
  echo $CROLE > $TARGET/etc/ngcp_ha_role
fi

# TODO: we probaby do not use /etc/ngcp_ha_master anymore, check it and clean
if "$PRO_EDITION" ; then
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
    die "Error: MAC address for $INTERNAL_DEV is same as for $EXTERNAL_DEV"
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
fi

if "$RETRIEVE_MGMT_CONFIG" && "$RESTART_NETWORK" ; then
  # restart networking for the time being only when running either in toram mode
  # or not booting from NFS, once we've finished the carrier setup procedure we
  # should be able to make this as our only supported default mode and drop
  # everything inside the 'else' statement...
  if grep -q 'toram' /proc/cmdline || ! grep -q 'root=/dev/nfs' /proc/cmdline ; then
    logit 'Set /etc/hosts from TARGET'
    cp ${TARGET}/etc/hosts /etc/hosts
    echo  'Restarting networking'
    logit 'Restarting networking'
    /etc/init.d/networking restart
  else
    # make sure we can access the management system which might be reachable
    # through a specific VLAN only
    ip link set dev "$INTERNAL_DEV" down # avoid conflicts with VLAN device(s)

    # vlan-raw-device bond0 doesn't exist in the live environment, if we don't
    # adjust it accordingly for our environment the vlan device(s) can't be
    # brought up
    # note: we do NOT modify the /e/n/i file from $TARGET here by intention
    sed -i "s/vlan-raw-device .*/vlan-raw-device eth0/" /etc/network/interfaces

    for interface in $(awk '/^auto vlan/ {print $2}' /etc/network/interfaces) ; do
      echo "Bringing up VLAN interface $interface"
      ifup "$interface"
    done
  fi # toram
fi

SIPWISE_HOME="/var/sipwise"
adduser_sipwise() {
  if "$NGCP_INSTALLER" ; then
    adduser_options="--disabled-password"	# NGCP
  else
    adduser_options="--disabled-login"		# Debian plain
  fi

  chroot $TARGET adduser sipwise --gecos "Sipwise" --home ${SIPWISE_HOME} --shell /bin/bash $adduser_options
}

get_installer_path() {
  if [ -z "$SP_VERSION" ] && ! $TRUNK_VERSION ; then
    INSTALLER=ngcp-installer-latest.deb

    if "$PRO_EDITION" ; then
      INSTALLER_PATH="http://${SIPWISE_REPO_HOST}/sppro/"
    else
      INSTALLER_PATH="http://${SIPWISE_REPO_HOST}/spce/"
    fi

    return # we don't want to run any further code from this function
  fi

  # use pool directory according for ngcp release
  if "$PRO_EDITION" ; then
    if "$CARRIER_EDITION" ; then
      local installer_package='ngcp-installer-carrier'
    else
      local installer_package='ngcp-installer-pro'
    fi
    local repos_base_path="http://${SIPWISE_REPO_HOST}/sppro/${SP_VERSION}/dists/${DEBIAN_RELEASE}/main/binary-amd64/"
    INSTALLER_PATH="http://${SIPWISE_REPO_HOST}/sppro/${SP_VERSION}/pool/main/n/ngcp-installer/"
  else
    local installer_package='ngcp-installer-ce'
    local repos_base_path="http://${SIPWISE_REPO_HOST}/spce/${SP_VERSION}/dists/${DEBIAN_RELEASE}/main/binary-amd64/"
    INSTALLER_PATH="http://${SIPWISE_REPO_HOST}/spce/${SP_VERSION}/pool/main/n/ngcp-installer/"
  fi

  # use a separate repos for trunk releases
  if $TRUNK_VERSION ; then
    local repos_base_path="http://${SIPWISE_REPO_HOST}/autobuild/dists/release-trunk-${DEBIAN_RELEASE}/main/binary-amd64/"
    INSTALLER_PATH="http://${SIPWISE_REPO_HOST}/autobuild/pool/main/n/ngcp-installer/"
  fi

  wget --timeout=30 -O Packages.gz "${repos_base_path}Packages.gz"
  # sed: display paragraphs matching the "Package: ..." string, then grab string "^Version: " and display the actual version via awk
  # sort -u to avoid duplicates in repositories shipping the ngcp-installer-pro AND ngcp-installer-pro-ha-v3 debs
  local version=$(zcat Packages.gz | sed "/./{H;\$!d;};x;/Package: ${installer_package}/b;d" | awk '/^Version: / {print $2}' | sort -u)

  [ -n "$version" ] || die "Error: installer version for ngcp ${SP_VERSION}, Debian release $DEBIAN_RELEASE with installer package $installer_package could not be detected."

  if "$CARRIER_EDITION" ; then
    INSTALLER="ngcp-installer-carrier_${version}_all.deb"
  elif "$PRO_EDITION" ; then
    INSTALLER="ngcp-installer-pro_${version}_all.deb"
  else
    INSTALLER="ngcp-installer-ce_${version}_all.deb"
  fi
}

set_repos() {
  cat > $TARGET/etc/apt/sources.list << EOF
# Please visit /etc/apt/sources.list.d/ instead.
EOF

  cat > $TARGET/etc/apt/sources.list.d/debian.list << EOF
## custom sources.list, deployed via deployment.sh

# Debian repositories
deb ${MIRROR} ${DEBIAN_RELEASE} main contrib non-free
EOF

  # drop this once Debian/jessie has security support
  if [ -n "$SEC_MIRROR" ] ; then
    echo "deb ${SEC_MIRROR} ${DEBIAN_RELEASE}-security main contrib non-free" \
      >> $TARGET/etc/apt/sources.list.d/debian.list
  else
    echo  "Warning: security mirror variable SEC_MIRROR is unset, not enabling security repository for $DEBIAN_RELEASE"
    logit "Warning: security mirror variable SEC_MIRROR is unset, not enabling security repository for $DEBIAN_RELEASE"
  fi

cat >> $TARGET/etc/apt/sources.list.d/debian.list << EOF
deb ${MIRROR} ${DEBIAN_RELEASE}-updates main contrib non-free
EOF

  # support testing rc releases without providing an according installer package ahead
  if [ -n "$AUTOBUILD_RELEASE" ] ; then
    echo "Running installer with sources.list for $DEBIAN_RELEASE + autobuild release-$AUTOBUILD_RELEASE"

    cat > $TARGET/etc/apt/sources.list.d/sipwise.list << EOF
## custom sources.list, deployed via deployment.sh

# Sipwise repositories
deb [arch=amd64] http://${SIPWISE_REPO_HOST}/autobuild/release/release-${AUTOBUILD_RELEASE} release-${AUTOBUILD_RELEASE} main
EOF
  fi
}

gen_installer_config () {
  mkdir -p "${TARGET}/etc/ngcp-installer/"

  if "$CARRIER_EDITION" ; then
    cat > ${TARGET}/etc/ngcp-installer/config_deploy.inc << EOF
CROLE="${CROLE}"
PXE_IMAGES_PATH="${PXE_IMAGES_PATH}"
EOF
  fi

  if "$PRO_EDITION" ; then
    cat >> ${TARGET}/etc/ngcp-installer/config_deploy.inc << EOF
HNAME="${ROLE}"
IP1="${IP1}"
IP2="${IP2}"
EIFACE="${EIFACE}"
EADDR="${EADDR}"
MCASTADDR="${MCASTADDR}"
DPL_MYSQL_REPLICATION="${DPL_MYSQL_REPLICATION}"
EOF
  fi

  cat >> ${TARGET}/etc/ngcp-installer/config_deploy.inc << EOF
FORCE=yes
SKIP_SOURCES_LIST="${SKIP_SOURCES_LIST}"
ADJUST_FOR_LOW_PERFORMANCE="${ADJUST_FOR_LOW_PERFORMANCE}"
ENABLE_VM_SERVICES="${ENABLE_VM_SERVICES}"
SIPWISE_REPO_HOST="${SIPWISE_REPO_HOST}"
SIPWISE_REPO_TRANSPORT="${SIPWISE_REPO_TRANSPORT}"
EOF

  cat "${TARGET}/etc/ngcp-installer/config_deploy.inc" > /tmp/ngcp-installer-cmdline.log
}

if "$NGCP_INSTALLER" ; then

  if "$RETRIEVE_MGMT_CONFIG" ; then
    password=sipwise
    echo "Retrieving SSH keys from management server (using password ${password})"

    mkdir -p "${TARGET}"/root/.ssh

    wget --timeout=30 -O "${TARGET}"/root/.ssh/authorized_keys "${MANAGEMENT_IP}:3000/ssh/authorized_keys"
    wget --timeout=30 -O "${TARGET}"/root/.ssh/id_rsa          "${MANAGEMENT_IP}:3000/ssh/id_rsa?password=${password}"
    wget --timeout=30 -O "${TARGET}"/root/.ssh/id_rsa.pub      "${MANAGEMENT_IP}:3000/ssh/id_rsa_pub"
    wget --timeout=30 -O "${TARGET}"/root/.ssh/known_hosts     "${MANAGEMENT_IP}:3000/ssh/known_hosts"

    chmod 600 "${TARGET}"/root/.ssh/authorized_keys
    chmod 600 "${TARGET}"/root/.ssh/id_rsa
    chmod 644 "${TARGET}"/root/.ssh/id_rsa.pub
    chmod 600 "${TARGET}"/root/.ssh/known_hosts

    wget --timeout=30 -O "${TARGET}"/etc/ssh/ssh_host_dsa_key     "${MANAGEMENT_IP}:3000/ssh/host_dsa_key?password=${password}"
    wget --timeout=30 -O "${TARGET}"/etc/ssh/ssh_host_dsa_key.pub "${MANAGEMENT_IP}:3000/ssh/host_dsa_key_pub"
    wget --timeout=30 -O "${TARGET}"/etc/ssh/ssh_host_rsa_key     "${MANAGEMENT_IP}:3000/ssh/host_rsa_key?password=${password}"
    wget --timeout=30 -O "${TARGET}"/etc/ssh/ssh_host_rsa_key.pub "${MANAGEMENT_IP}:3000/ssh/host_rsa_key_pub"

    chmod 600 "${TARGET}"/etc/ssh/ssh_host_dsa_key
    chmod 644 "${TARGET}"/etc/ssh/ssh_host_dsa_key.pub
    chmod 600 "${TARGET}"/etc/ssh/ssh_host_rsa_key
    chmod 644 "${TARGET}"/etc/ssh/ssh_host_rsa_key.pub
  fi

  # add sipwise user
  adduser_sipwise

  # set INSTALLER_PATH and INSTALLER depending on release/version
  get_installer_path

  # generate debian/sipwise repos
  set_repos

  if "$CARRIER_EDITION"; then
    logit "Mounting GRML image for ngcpcfg-api in ngcp-installer..."
    mkdir -p "${TARGET}/$PXE_IMAGES_PATH"
    mount --read-only --bind "$GRML_PXE_IMAGES_PATH" "${TARGET}/$PXE_IMAGES_PATH"
  fi

  set_deploy_status "ngcp-installer"

  # install ngcp-installer
  logit "ngcp-installer: $INSTALLER"
  cat << EOT | grml-chroot $TARGET /bin/bash
wget ${INSTALLER_PATH}/${INSTALLER}
dpkg -i $INSTALLER
EOT

  # generate installer configs
  gen_installer_config

  # execute ngcp-installer
  cat << EOT | grml-chroot $TARGET /bin/bash
ngcp-installer 2>&1 | tee -a /tmp/ngcp-installer-debug.log
RC=\${PIPESTATUS[0]}
if [ \$RC -ne 0 ] ; then
  echo "Fatal error while running ngcp-installer:" >&2
  tail -10 /tmp/ngcp-installer.log
  exit \$RC
fi
EOT

  # baby, something went wrong!
  if [ $? -eq 0 ] ; then
    logit "installer: success"
  else
    logit "installer: error"
    die "Error during installation of ngcp. Find details at: $TARGET/tmp/ngcp-installer.log $TARGET/tmp/ngcp-installer-debug.log"
  fi

  if "$PRO_EDITION" ; then
    # set variable to have the *other* node from the PRO setup available for ngcp-network
    case $ROLE in
      sp1)
        logit "Role matching sp1"
        if [ -n "$TARGET_HOSTNAME" ] && [[ "$TARGET_HOSTNAME" == *a ]] ; then # usually carrier env
          logit "Target hostname is set and ends with 'a'"
          THIS_HOST="$TARGET_HOSTNAME"
          PEER="${TARGET_HOSTNAME%a}b"
        else # usually PRO env
          logit "Target hostname is not set or does not end with 'a'"
          THIS_HOST="$ROLE"
          PEER=sp2
        fi
        ;;
      sp2)
        logit "Role matching sp2"
        if [ -n "$TARGET_HOSTNAME" ] && [[ "$TARGET_HOSTNAME" == *b ]] ; then # usually carrier env
          THIS_HOST="$TARGET_HOSTNAME"
          PEER="${TARGET_HOSTNAME%b}a"
        else # usually PRO env
          logit "Target hostname is not set or does not end with 'b'"
          THIS_HOST="$ROLE"
          PEER=sp1
        fi
        ;;
      *)
        logit "Using unsupported role: $ROLE"
        ;;
    esac
  fi

  if "$RETRIEVE_MGMT_CONFIG" ; then
    if [ "$ROLE" = "sp1" ] ; then
      password=sipwise

      logit "Retrieving sipwise.cnf from management server (using password ${password})"
      wget --timeout=30 -O "${TARGET}"/etc/mysql/sipwise.cnf "${MANAGEMENT_IP}:3000/dbconfig/sipwise_cnf?password=${password}"
      logit "Copying sipwise.cnf to /mnt/glusterfs/shared_config"
      chroot $TARGET cp /etc/mysql/sipwise.cnf /mnt/glusterfs/shared_config/sipwise.cnf

      logit "Sync constants"
      chroot $TARGET ngcp-sync-constants -r
    fi
  fi

  case "$CROLE" in
     proxy)
        if grml-chroot $TARGET /etc/init.d/mysql start 2 ; then
          logit "Configuring MySQL second instance"
          chroot $TARGET /usr/share/ngcp-ngcpcfg/helper/check-for-mysql 10 2
          chroot $TARGET ngcp-sync-constants -r -s --local-repl
        else
          logit "Can't start MySQL second instance"
        fi
        ;;
  esac

  # make sure all services are stopped
  for service in \
    apache2 \
    asterisk \
    collectd \
    dnsmasq \
    exim4 \
    irqbalance \
    kamailio-lb \
    kamailio-proxy \
    mediator \
    monit \
    mysql \
    nfs-kernel-server \
    ngcp-rate-o-mat \
    ngcp-rtpengine-daemon \
    ngcp-sems \
    ntp \
    rsyslog \
    sems ; \
  do
    if [ -f $TARGET/etc/init.d/$service ] ; then
      chroot $TARGET /etc/init.d/$service stop || true
    fi
  done

  if [ -f $TARGET/etc/init.d/prosody ] ; then
    # prosody's init script requires mounted /proc
    grml-chroot $TARGET /etc/init.d/prosody stop || true
  fi

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
if "$RETRIEVE_MGMT_CONFIG" ; then
  echo "Nothing to do (RETRIEVE_MGMT_CONFIG is set), network.yml was already set up."
elif "$PRO_EDITION" ; then
  # get list of available network devices (excl. some known-to-be-irrelevant ones, also see MT#8297)
  net_devices=$(tail -n +3 /proc/net/dev | awk -F: '{print $1}'| sed "s/\s*//" | grep -ve '^vmnet' -ve '^vboxnet' -ve '^docker' -ve '^usb' | sort -u)

  NETWORK_DEVICES=""
  for network_device in $net_devices $DEFAULT_INSTALL_DEV $INTERNAL_DEV $EXTERNAL_DEV ; do
    # avoid duplicates
    echo "$NETWORK_DEVICES" | grep -wq "$network_device" || NETWORK_DEVICES="$NETWORK_DEVICES $network_device"
  done
  export NETWORK_DEVICES
  unset net_devices

  cat << EOT | grml-chroot $TARGET /bin/bash
  if ! [ -r /etc/ngcp-config/network.yml ] ; then
    echo '/etc/ngcp-config/network.yml does not exist'
    exit 0
  fi

  if [ "$ROLE" = "sp1" ] ; then
    cp /etc/ngcp-config/network.yml /etc/ngcp-config/network.yml.factory_default

    ngcp-network --host=$THIS_HOST --set-interface=lo --ip=auto --netmask=auto --hwaddr=auto --ipv6='::1' --type=web_int
    ngcp-network --host=$THIS_HOST --set-interface=$DEFAULT_INSTALL_DEV --shared-ip=none --shared-ipv6=none
    ngcp-network --host=$THIS_HOST --set-interface=$DEFAULT_INSTALL_DEV --ip=auto --netmask=auto --hwaddr=auto
    ngcp-network --host=$THIS_HOST --set-interface=$INTERNAL_DEV --ip=auto --netmask=auto --hwaddr=auto
    nameserver="$(awk '/^nameserver/ {print $2}' /etc/resolv.conf)"
    for entry in \$nameserver ; do
      ngcp-network --host=$THIS_HOST --set-interface=$DEFAULT_INSTALL_DEV --dns=\$entry
    done

    GW=$(ip route show dev $DEFAULT_INSTALL_DEV | awk '/^default via/ {print $3}')
    if [ -n "\$GW" ] ; then
      ngcp-network --host=$THIS_HOST --set-interface=$DEFAULT_INSTALL_DEV --gateway="\$GW"
    fi

    ngcp-network --host=$THIS_HOST --peer=$PEER
    ngcp-network --host=$THIS_HOST --move-from=lo --move-to=$INTERNAL_DEV --type=ha_int
    # set *_ext types accordingly for PRO setup
    ngcp-network --host=$THIS_HOST --move-from=lo --move-to=$EXTERNAL_DEV \
                                   --type=sip_ext --type=rtp_ext --type=mon_ext
    ngcp-network --host=$THIS_HOST --set-interface=$EXTERNAL_DEV --type=web_ext

    ngcp-network --host=$PEER --peer=$THIS_HOST
    ngcp-network --host=$PEER --set-interface=$EXTERNAL_DEV --shared-ip=none --shared-ipv6=none
    ngcp-network --host=$PEER --set-interface=lo --ipv6='::1' --ip=auto --netmask=auto --hwaddr=auto

    # add ssh_ext to all the interfaces of sp1 on sp1
    for interface in \$NETWORK_DEVICES ; do
      ngcp-network --host=$THIS_HOST --set-interface=\$interface --type=ssh_ext
    done

    # add ssh_ext to lo and $INTERNAL_DEV interfaces of sp2 on sp1 so we can reach the ssh server at any time
    ngcp-network --host=$PEER --set-interface=lo --type=ssh_ext
    ngcp-network --host=$PEER --set-interface=$INTERNAL_DEV --type=ssh_ext

    # needed to make sure MySQL setup is OK for first node until second node is set up
    ngcp-network --host=$PEER --set-interface=$INTERNAL_DEV --ip=$IP2 --netmask=$DEFAULT_INTERNAL_NETMASK --type=ha_int
    ngcp-network --host=$PEER --role=proxy --role=lb --role=mgmt --role=rtp --role=db
    ngcp-network --host=$PEER --set-interface=lo --type=sip_int --type=web_int --type=web_ext --type=aux_ext

    # version >= mr3.5, previous versions has no dbnode option
    ngcp-network --host=$PEER --dbnode=2 || true

    cp /etc/ngcp-config/network.yml /mnt/glusterfs/shared_config/network.yml

    # use --no-db-sync only if supported by ngcp[cfg] version
    if grep -q -- --no-db-sync /usr/sbin/ngcpcfg ; then
      ngcpcfg --no-db-sync commit "deployed /etc/ngcp-config/network.yml on $ROLE"
    else
      ngcpcfg commit "deployed /etc/ngcp-config/network.yml on $ROLE"
    fi

    ngcpcfg build
    ngcpcfg push --shared-only
  else # ROLE = sp2
    ngcpcfg pull
    ngcp-network --host=$THIS_HOST --set-interface=$DEFAULT_INSTALL_DEV --ip=auto --netmask=auto --hwaddr=auto

    # finalize the --ip=$IP2 from previous run on first node
    ngcp-network --host=$THIS_HOST --set-interface=$INTERNAL_DEV --ip=auto --netmask=auto --hwaddr=auto --type=ha_int
    # set *_ext types accordingly for PRO setup
    ngcp-network --host=$THIS_HOST --set-interface=$EXTERNAL_DEV --type=web_int --type=web_ext --type=sip_ext \
                              --type=rtp_ext --type=mon_ext

    # add ssh_ext to all the interfaces of sp2 on sp2
    for interface in \$NETWORK_DEVICES ; do
      ngcp-network --host=$THIS_HOST --set-interface=\$interface --type=ssh_ext
    done

    # use --no-db-sync only if supported by ngcp[cfg] version
    if grep -q -- --no-db-sync /usr/sbin/ngcpcfg ; then
      ngcpcfg --no-db-sync commit "deployed /etc/ngcp-config/network.yml on $ROLE"
    else
      ngcpcfg commit "deployed /etc/ngcp-config/network.yml on $ROLE"
    fi

    ngcpcfg push --shared-only

    # make sure login from second node to first node works
    ssh-keyscan $PEER >> ~/.ssh/known_hosts

    # live system uses a different SSH host key than the finally installed
    # system, so do NOT use ssh-keyscan here
    tail -1 ~/.ssh/known_hosts | sed "s/\w* /$THIS_HOST /" >> ~/.ssh/known_hosts
    tail -1 ~/.ssh/known_hosts | sed "s/\w* /$MANAGEMENT_IP /" >> ~/.ssh/known_hosts
    scp ~/.ssh/known_hosts $PEER:~/.ssh/known_hosts

    ssh $PEER ngcpcfg pull
    ngcpcfg build

    if ngcpcfg --help |grep -q init-mgmt ; then
      ngcpcfg init-mgmt $MANAGEMENT_IP
    else
      echo "Skipping ngcpcfg init-mgmt as it is not available"
    fi
  fi
EOT
fi

if "$RETRIEVE_MGMT_CONFIG" ; then
  echo "Nothing to do (RETRIEVE_MGMT_CONFIG is set), /etc/network/interfaces was already set up."
elif ! "$NGCP_INSTALLER" ; then
  echo "Not modifying /etc/network/interfaces as installing plain Debian."
elif "$DHCP" ; then
  cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto $EXTERNAL_DEV
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

auto vlan${VLANID}
iface vlan${VLANID} inet static
        address $(ifdata -pa $EXTERNAL_DEV)
        netmask $(ifdata -pn $EXTERNAL_DEV)
        gateway $(route -n | awk '/^0\.0\.0\.0/{print $2; exit}')
        dns-nameservers $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | xargs echo -n)
        vlan-raw-device $VLANIF

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
  elif "$PRO_EDITION" && "$BONDING" ; then
    cat > $TARGET/etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface
auto lo
iface lo inet loopback

auto bond0
iface bond0 inet static
        bond-slaves $EXTERNAL_DEV $INTERNAL_DEV
        bond_mode 802.3ad
        bond_miimon 100
        bond_lacp_rate 1
        address $(ifdata -pa $EXTERNAL_DEV)
        netmask $(ifdata -pn $EXTERNAL_DEV)
        gateway $(route -n | awk '/^0\.0\.0\.0/{print $2; exit}')
        dns-nameservers $(awk '/^nameserver/ {print $2}' /etc/resolv.conf | xargs echo -n)

# additional possible bonding mode
# auto bond0
# iface bond0 inet manual
#         bond-slaves eth0 eth1
#         bond_mode active-backup
#         bond_miimon 100

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
127.0.0.2 $TARGET_HOSTNAME. $TARGET_HOSTNAME
EOF
  fi

}

fake_uname() {
   cat > "${TARGET}/tmp/uname.c" << EOF
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syslog.h>
#include <sys/utsname.h>

#ifndef UTS_RELEASE
#define UTS_RELEASE "0.0.0"
#endif

#ifndef RTLD_NEXT
#define RTLD_NEXT      ((void *) -1l)
#endif

typedef int (*uname_t) (struct utsname * buf);

static void *get_libc_func(const char *funcname)
{
  void *func;
  char *error;

  func = dlsym(RTLD_NEXT, funcname);
  if ((error = dlerror()) != NULL) {
    fprintf(stderr, "Can't locate libc function \`%s' error: %s", funcname, error);
    _exit(EXIT_FAILURE);
  }
  return func;
}

int uname(struct utsname *buf)
{
  int ret;
  char *env = NULL;
  uname_t real_uname = (uname_t) get_libc_func("uname");

  ret = real_uname((struct utsname *) buf);
  strncpy(buf->release, ((env = getenv("UTS_RELEASE")) == NULL) ? UTS_RELEASE : env, 65);
  return ret;
}
EOF

  grml-chroot "$TARGET" gcc -shared -fPIC -ldl /tmp/uname.c -o /tmp/fake-uname.so || die 'Failed to build fake-uname.so'

  # avoid "ERROR: ld.so: object '/tmp/fake-uname.so' from LD_PRELOAD cannot be preloaded: ignored."
  # messages caused by the host system when running grml-chroot process
  cp "$TARGET"/tmp/fake-uname.so /tmp/fake-uname.so
}

vagrant_configuration() {
  # if ngcp-keyring isn't present (e.g. on plain Debian systems) then we have
  # to install our key for usage of our own Debian mirror
  if grml-chroot "${TARGET}" apt-key list | grep -q 680FBA8A ; then
    echo "Sipwise Debian mirror key is already present."
  else
    echo "Installing Sipwise Debian mirror key (680FBA8A)."
    grml-chroot "${TARGET}" wget -O /etc/apt/680FBA8A.asc http://${SIPWISE_REPO_HOST}/autobuild/680FBA8A.asc
    grml-chroot "${TARGET}" apt-key add /etc/apt/680FBA8A.asc
  fi

  # make sure we use the most recent package versions, including apt-key setup
  grml-chroot "${TARGET}" apt-get update

  # bzip2, linux-headers-amd64 and make are required for VirtualBox Guest Additions installer
  # less + sudo are required for Vagrant itself
  echo "Installing software for VirtualBox Guest Additions installer"
  # there's no linux-headers-amd64 package in squeeze:
  case "$DEBIAN_RELEASE" in
    squeeze) local linux_headers_package="linux-headers-2.6-amd64" ;;
          *) local linux_headers_package="linux-headers-amd64"     ;;
  esac
  chroot "$TARGET" apt-get -y install bzip2 less ${linux_headers_package} make sudo
  if [ $? -ne 0 ] ; then
    die "Error: failed to install 'bzip2 less ${linux_headers_package} make sudo' packages."
  fi

  ngcp_vmbuilder='/tmp/ngcp-vmbuilder/'
  if [ -d "${ngcp_vmbuilder}" ] ; then
    echo "Checkout of ngcp-vmbuilder exists already, nothing to do"
  else
    echo "Checking out ngcp-vmbuilder git repository"
    git clone git://git.mgm.sipwise.com/vmbuilder "${ngcp_vmbuilder}"
  fi

  echo "Adjusting sudo configuration"
  mkdir -p "${TARGET}/etc/sudoers.d"
  echo "sipwise ALL=NOPASSWD: ALL" > "${TARGET}/etc/sudoers.d/vagrant"
  chmod 0440 "${TARGET}/etc/sudoers.d/vagrant"

  if chroot $TARGET getent passwd | grep '^sipwise' ; then
    echo "User sipwise exists already, nothing to do"
  else
    echo "Adding user sipwise"
    adduser_sipwise
  fi

  if grep -q '^# Added for Vagrant' "${TARGET}/${SIPWISE_HOME}/.profile" 2>/dev/null ; then
    echo "PATH configuration for user Sipwise is already adjusted"
  else
    echo "Adjusting PATH configuration for user Sipwise"
    echo "# Added for Vagrant" >> "${TARGET}/${SIPWISE_HOME}/.profile"
    echo "PATH=\$PATH:/sbin:/usr/sbin" >> "${TARGET}/${SIPWISE_HOME}/.profile"
  fi

  echo "Adjusting ssh configuration for user sipwise"
  mkdir -p "${TARGET}/${SIPWISE_HOME}/.ssh/"
  cat $ngcp_vmbuilder/config/id_rsa_sipwise.pub >> "${TARGET}/${SIPWISE_HOME}/.ssh/authorized_keys"
  chroot "${TARGET}" chown sipwise:sipwise ${SIPWISE_HOME}/.ssh ${SIPWISE_HOME}/.ssh/authorized_keys

  echo "Adjusting ssh configuration for user root"
  mkdir -p "${TARGET}/root/.ssh/"
  cat $ngcp_vmbuilder/config/id_rsa_sipwise.pub >> "${TARGET}/root/.ssh/authorized_keys"

  # see https://github.com/mitchellh/vagrant/issues/1673
  # and https://bugs.launchpad.net/ubuntu/+source/xen-3.1/+bug/1167281
  if grep -q 'adjusted for Vagrant' "${TARGET}/root/.profile" ; then
    echo "Workaround for annoying bug 'stdin: is not a tty' Vagrant message seems to be present already"
  else
    echo "Adding workaround for annoying bug 'stdin: is not a tty' Vagrant message"
    sed -ri -e "s/mesg\s+n/# adjusted for Vagrant\ntty -s \&\& mesg n/" "${TARGET}/root/.profile"
  fi

  install_vbox_package

  # required for fake_uname and VBoxLinuxAdditions.run
  grml-chroot $TARGET apt-get update
  grml-chroot $TARGET apt-get -y install libc6-dev gcc
  fake_uname

  KERNELHEADERS=$(basename $(ls -d ${TARGET}/usr/src/linux-headers*amd64 | grep -v -- -rt-amd64 | sort -u -r -V | head -1))
  if [ -z "$KERNELHEADERS" ] ; then
    die "Error: no kernel headers found for building the VirtualBox Guest Additions kernel module."
  fi
  KERNELVERSION=${KERNELHEADERS##linux-headers-}
  if [ -z "$KERNELVERSION" ] ; then
    die "Error: no kernel version could be identified."
  fi

  vbox_isofile="/usr/share/virtualbox/VBoxGuestAdditions.iso"
  if [ ! -r "$vbox_isofile" ] ; then
    die "Error: could not find $vbox_isofile"
  fi

  mkdir -p "${TARGET}/media/cdrom"
  mountpoint "${TARGET}/media/cdrom" >/dev/null && umount "${TARGET}/media/cdrom"
  mount -t iso9660 "${vbox_isofile}" "${TARGET}/media/cdrom/"
  UTS_RELEASE=$KERNELVERSION LD_PRELOAD=/tmp/fake-uname.so grml-chroot "$TARGET" /media/cdrom/VBoxLinuxAdditions.run --nox11
  tail -10 "${TARGET}/var/log/VBoxGuestAdditions.log"
  umount "${TARGET}/media/cdrom/"

  # work around regression in virtualbox-guest-additions-iso 4.3.10
  if [ -d ${TARGET}/opt/VBoxGuestAdditions-4.3.10 ] ; then
    echo "Installing VBoxGuestAddition symlink to work around vbox 4.3.10 issue"
    ln -s /opt/VBoxGuestAdditions-4.3.10/lib/VBoxGuestAdditions ${TARGET}/usr/lib/VBoxGuestAdditions
  fi

  # VBoxLinuxAdditions.run chooses /usr/lib64 as soon as this directory exists, which
  # is the case for our PRO systems shipping the heartbeat-2 package; then the
  # symlink /sbin/mount.vboxsf points to the non-existing /usr/lib64/VBoxGuestAdditions/mount.vboxsf
  # file instead of pointing to /usr/lib/x86_64-linux-gnu/VBoxGuestAdditions/mount.vboxsf
  if ! chroot "$TARGET" readlink -f /sbin/mount.vboxsf ; then
    echo "Installing mount.vboxsf symlink to work around /usr/lib64 issue"
    ln -sf /usr/lib/x86_64-linux-gnu/VBoxGuestAdditions/mount.vboxsf ${TARGET}/sbin/mount.vboxsf
  fi

  # MACs are different on buildbox and on local VirtualBox
  # see http://ablecoder.com/b/2012/04/09/vagrant-broken-networking-when-packaging-ubuntu-boxes/
  echo "Removing /etc/udev/rules.d/70-persistent-net.rules"
  rm -f "${TARGET}/etc/udev/rules.d/70-persistent-net.rules"
}

if "$RETRIEVE_MGMT_CONFIG" ; then
  echo "Nothing to do, /etc/hosts was already set up."
else
  echo "Generating /etc/hosts"
  generate_etc_hosts
fi

if "$VAGRANT" ; then
  echo "Bootoption vagrant present, executing vagrant_configuration."
  vagrant_configuration
fi

if [ -n "$PUPPET" ] ; then
  echo "Rebuilding /etc/hosts"
  cat > $TARGET/etc/hosts << EOF
# Generated via deployment.sh
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

EOF

  echo "Setting hostname to $TARGET_HOSTNAME"
  echo "$TARGET_HOSTNAME" > ${TARGET}/etc/hostname
  grml-chroot $TARGET /etc/init.d/hostname.sh

  chroot $TARGET apt-get -y install resolvconf libnss-myhostname

  chroot $TARGET sed -i 's/START=.*/START=yes/' /etc/default/puppet

  cat > ${TARGET}/etc/puppet/puppet.conf << EOF
# Deployed via deployment.sh
[main]
logdir=/var/log/puppet
vardir=/var/lib/puppet
ssldir=/var/lib/puppet/ssl
rundir=/var/run/puppet
factpath=$vardir/lib/facter
templatedir=$confdir/templates
prerun_command=/etc/puppet/etckeeper-commit-pre
postrun_command=/etc/puppet/etckeeper-commit-post
server=puppet.mgm.sipwise.com

[master]
ssl_client_header=SSL_CLIENT_S_DN
ssl_client_verify_header=SSL_CLIENT_VERIFY

[agent]
environment=$PUPPET
EOF

  grml-chroot $TARGET puppet agent --test --waitforcert 30 2>&1 | tee -a /tmp/puppet.log || true
fi

# make sure we don't leave any running processes
for i in asterisk atd collectd collectdmon dbus-daemon exim4 \
         glusterd glusterfs glusterfsd glusterfs-server haveged monit nscd \
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
  databases=$(chroot $TARGET mysql -B -N -e 'show databases' | grep -ve '^information_schema$' -ve '^mysql$' -ve '^performance_schema$')

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

if [ -r "${INSTALL_LOG}" ] && [ -d "${TARGET}"/var/log/ ] ; then
  cp "${INSTALL_LOG}" "${TARGET}"/var/log/
fi

# don't leave any mountpoints
sync
if "$CARRIER_EDITION"; then
  umount ${TARGET}/$PXE_IMAGES_PATH  2>/dev/null || true
fi
umount ${TARGET}/proc       2>/dev/null || true
umount ${TARGET}/sys        2>/dev/null || true
umount ${TARGET}/dev/pts    2>/dev/null || true
umount ${TARGET}/dev        2>/dev/null || true
chroot ${TARGET} umount -a  2>/dev/null || true
sync

# unmount chroot - what else?
umount $TARGET || umount -l $TARGET # fall back if a process is still being active

if "$LVM" ; then
  # make sure no device mapper handles are open, otherwise
  # rereading partition table won't work
  dmsetup remove_all || true
fi

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

set_deploy_status "finished"

# if ngcpstatus boot option is used wait for a specific so a
# remote host has a chance to check for deploy status "finished",
# defaults to 0 seconds otherwise
sleep "$STATUS_WAIT"

if "$INTERACTIVE" ; then
  exit 0
fi

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

  for key in s u o ; do
    echo $key > /proc/sysrq-trigger
    sleep 2
  done
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
