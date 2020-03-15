#!/bin/sh
#
# this script update the ethernet and port informations
#
# it is better to run this script in the var directory

echo "Retrieving the ethernet vendor codes:"

#wget -N http://standards.ieee.org/develop/regauth/oui/oui.txt

curl http://standards.ieee.org/develop/regauth/oui/oui.txt -o oui.txt

echo "Retrieving port numbers:"

#wget -N http://www.iana.org/assignments/port-numbers

#curl http://www.iana.org/assignments/port-numbers -o port-numbers

# 2013 

# file has moved to xml
# http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml
#curl http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt -o port-numbers

#echo "CR NL to NL (unix) conversion on port-numbers file"

# remove RETURN chars
#tr -d '\r' < port-numbers >  port-numbers.txt

#rm port-numbers
cp /etc/services port-numbers.txt

echo

echo "Now run preformat_ether.pl and preformat_ports.pl"
