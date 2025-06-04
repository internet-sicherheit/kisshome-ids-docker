#!/bin/bash
#
# Downloaded from https://raw.githubusercontent.com/ntop/ntopng/dev/tools/fritzdump.sh

# This is the address of the router
FRITZIP=http://192.168.188.1

# This is the WAN interface
#IFACE="2-0"

# This is the routing interface
#IFACE="3-0"

# Lan Interface
#IFACE="2-lan"

# Wlan Interface
#IFACE="1-wlan0"

# Guest Network
IFACE="1-guest"

# If you use password-only authentication use 'dslf-config' as username.
FRITZUSER=
FRITZPWD=

SIDFILE="/tmp/fritz.sid"

if [ -z "$FRITZPWD" ] || [ -z "$FRITZUSER" ]  ; then echo "Username/Password empty. Usage: $0 <username> <password>" ; exit 1; fi

echo "Trying to login into $FRITZIP as user $FRITZUSER"

if [ ! -f $SIDFILE ]; then
  touch $SIDFILE
fi

SID=$(cat $SIDFILE)

# Request challenge token from Fritz!Box
CHALLENGE=$(curl -k -s $FRITZIP/login_sid.lua |  grep -o "<Challenge>[a-z0-9]\{8\}" | cut -d'>' -f 2)

# Very proprieatry way of AVM: Create a authentication token by hashing challenge token with password
HASH=$(perl -MPOSIX -e '
    use Digest::MD5 "md5_hex";
    my $ch_Pw = "$ARGV[0]-$ARGV[1]";
    $ch_Pw =~ s/(.)/$1 . chr(0)/eg;
    my $md5 = lc(md5_hex($ch_Pw));
    print $md5;
  ' -- "$CHALLENGE" "$FRITZPWD")
  curl -k -s "$FRITZIP/login_sid.lua" -d "response=$CHALLENGE-$HASH" -d 'username='${FRITZUSER} | grep -o "<SID>[a-z0-9]\{16\}" | cut -d'>' -f 2 > $SIDFILE

SID=$(cat $SIDFILE)

# Check for successfull authentification
if [[ $SID =~ ^0+$ ]] ; then echo "Login failed. Did you create & use explicit Fritz!Box users?" ; exit 1 ; fi

echo "Capturing traffic on Fritz!Box interface $IFACE ..." 1>&2

# In case you want to use tshark, ntopng or wireshark
#wget --no-check-certificate -qO- $FRITZIP/cgi-bin/capture_notimeout?ifaceorminor=$IFACE\&snaplen=\&capture=Start\&sid=$SID | /usr/bin/tshark -i -
#wget --no-check-certificate -qO- $FRITZIP/cgi-bin/capture_notimeout?ifaceorminor=$IFACE\&snaplen=\&capture=Start\&sid=$SID | ntopng -i -
#wget --no-check-certificate -qO- $FRITZIP/cgi-bin/capture_notimeout?ifaceorminor=$IFACE\&snaplen=\&capture=Start\&sid=$SID | /usr/bin/wireshark -i -

# To test if its working
#wget --no-check-certificate --timeout 0 $FRITZIP/cgi-bin/capture_notimeout?ifaceorminor=$IFACE\&snaplen=\&capture=Start\&sid=$SID -O ~/pcaps/test.pcap

# Start capturing network traffic
#wget --no-check-certificate --timeout 0 -qO- $FRITZIP/cgi-bin/capture_notimeout?ifaceorminor=$IFACE\&snaplen=\&capture=Start\&sid=$SID | /usr/bin/tshark -i - -q -b duration:86400 -w ~/pcaps/$IFACE.pcap

# Interval instead of duration
#wget --no-check-certificate --timeout 0 -qO- $FRITZIP/cgi-bin/capture_notimeout?ifaceorminor=$IFACE\&snaplen=\&capture=Start\&sid=$SID | /usr/bin/tshark -i - -q -b interval:86400 -w ~/pcaps/$IFACE.pcap

wget --no-check-certificate --timeout 0 -qO- $FRITZIP/cgi-bin/capture_notimeout?ifaceorminor=$IFACE\&snaplen=\&capture=Start\&sid=$SID | curl -X POST http://localhost:5000/dockerapi/pcapstream
