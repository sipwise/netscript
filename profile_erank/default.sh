# example profile
#
# profiles contain deployment site specific configurations
# this one is for erank's VMs


# SP_VERSION=2.3
# INSTALLER_VERSION=0.5.3

# internal IP addresses of sp1/sp2 (on eth1)
IP1=192.168.51.133
IP2=192.168.51.134
# INTERNAL_NETMASK=192.168.255.248      # TODO: has to be enabled in deployment.sh

if "$PRO_EDITION" ; then
  case "$ROLE" in
    sp1) EADDR=77.244.249.112 ;     # external IP address of sp1
    	 EIFACE=eth0 ;;             # on interface ...
    sp2) EADDR=77.244.249.113 ;     # external IP address of sp2
    	 EIFACE=eth0 ;;             # on interface ...
  esac
  MCASTADDR=226.94.1.1 ;            # multicast address
else
  EADDR=77.244.249.109 ;            # external IP address of ce server
  EIFACE=eth0 ;                     # on interface ...
fi

