#!/bin/bash

# better safe than sorry
export LC_ALL=C
export LANG=C

TIMEOUT=30

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

# boot option check
if checkBootParam ngcpvers ; then
  SP_VERSION=$(getBootParam ngcpvers)
fi

if [ -z "$SP_VERSION" ] ; then
  MSG="ngcp version is unspecified, assuming master/trunk therefore."
  SP_VERSION="master"
elif [ "$SP_VERSION" = "trunk" ] ; then
  SP_VERSION="master"
fi

display_logo() {
  echo -ne "\ec\e[1;32m"
  clear
  echo "### This deployment script version is OUTDATED. ### "
  echo ""
  echo "Please use an up2date version of the install CD/deployment system."
  [ -n "$MSG" ] && echo "$MSG"
  echo "Downloading + executing deployment script for ngcp $SP_VERSION in $TIMEOUT seconds."
  echo -ne "\e[10;0r"
  echo -ne "\e[9B\e[1;m"
}

display_logo
sleep $TIMEOUT
wget --timeout=30 -O "/tmp/deployment_${SP_VERSION}" "http://deb.sipwise.com/netscript/${SP_VERSION}/deployment.sh"

bash "/tmp/deployment_${SP_VERSION}"

## END OF FILE #################################################################1
