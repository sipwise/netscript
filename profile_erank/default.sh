# example profile
#
# profiles contain deployment site specific configurations
# this one is for erank's VMs

## INSTALLER CONFIG
# choose a specific SP release version AND installer version
# (both or none!), default: use latest installer and release
# SP_VERSION=2.3
# INSTALLER_VERSION=0.5.3

## SIPWISE PROVIDER CONFIG

if "$PRO_EDITION" ; then
  EADDR=77.244.249.114                 # external cluster address
  EIFACE=eth0                          # external cluster device
  EXTERNAL_DEV=eth0                    # external device (==EIFACE, or trouble!)
  TARGET_DOMAIN=.mgm.sipwise.com
  case "$ROLE" in
    sp1) EXTERNAL_IP=77.244.249.112 ;  # external IP address of sp1
         TARGET_HOSTNAME=mysp1 ;; 
    sp2) EXTERNAL_IP=77.244.249.113 ;  # external IP address of sp2
         TARGET_HOSTNAME=mysp2 ;; 
  esac
  IP1=192.168.255.249                  # internal IP addresses of sp1
  IP2=192.168.255.250                  # internal IP addresses of sp2
  INTERNAL_NETMASK=255.255.255.248     # 
else  # CE_EDITION
  EADDR=77.244.249.109 ;               # external IP address of ce server
  EIFACE=eth0 ;                        # on interface ...
fi

