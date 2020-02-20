
# Makefile.am for S.N.I.F by Damien MATTEI

AUTOMAKE_OPTIONS=foreign

sbin_PROGRAMS=snif

snif_SOURCES=snif.c snif.h \
var.h \
dnscache.h \
ethernet.c ethernet.h \
tokenring.c tokenring.h \
fddi.c fddi.h \
llc.c llc.h \
snap.c snap.h \
enc.c enc.h \
ppp.c ppp.h \
pppserial.c \
slip.c slip.h \
wifi.c wifi.h \
chdlc.c chdlc.h \
sll.c sll.h \
pflog.c pflog.h \
oldpflog.c oldpflog.h \
eap.c eap.h \
pppoe.c pppoe.h \
loopback.c loopback.h \
raw.c \
i4lrawip.c \
i4lciscoip.c \
vlan.c vlan.h \
arp.c \
ip.c ip.h \
ipv6.c ipv6.h\
ipx.c \
ethlb.c \
icmp.c icmp.h \
tcp.c tcp.h \
udp.c udp.h \
gre.c gre.h \
terminal.h \
color.h


#AM_CPPFLAGS = -I/usr/include/pcap

snif_LDADD = -lpcap \
sfutil/libsfutil.a

SUBDIRS = sfutil

INCLUDES = @INCLUDES@

data_DATA = var/ieee_ethercodes.dat var/portnumbers.dat
