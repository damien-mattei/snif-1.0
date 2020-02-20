/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@orange.fr>

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 ****************************************************************************/

void DecodeLoopBackPkt(struct pcap_pkthdr * , u_int8_t * ); /*  Decoding on loopback devices. */
void DecodeRawPkt(struct pcap_pkthdr *, u_int8_t *); /* Decodes packets coming in raw on layer 2, like PPP. */
void DecodeSlipPkt(struct pcap_pkthdr * , u_int8_t * ); /* Decode SLIP traffic */
void DecodeEthPkt(struct pcap_pkthdr *, u_int8_t *); /* Decode Ethernet packets */
void DecodePppPkt(struct pcap_pkthdr * , u_int8_t *); /* Decode PPP traffic */
void DecodeTokenRingPkt(struct pcap_pkthdr *, u_int8_t *); /* Decode Token Ring packets */
void DecodeFDDIPkt(struct pcap_pkthdr *, u_int8_t *); /* Decode FDDI Packet */
void DecodeIEEE80211Pkt(struct pcap_pkthdr * , u_int8_t * ); /* Decode Wifi Packet */
void DecodeLinuxSLLPkt(struct pcap_pkthdr * , u_int8_t *); /* Decode linux cooked sockets */
void DecodeChdlcPkt(struct pcap_pkthdr *, u_int8_t *); /* Decodes Cisco HDLC encapsulated packets */
void DecodePflog(struct pcap_pkthdr * , u_int8_t *); /* Decode pflog device packets */
void DecodeOldPflog(struct pcap_pkthdr * , u_int8_t *); /* Decode old pflog device packets */
void DecodePppSerialPkt(struct pcap_pkthdr *, u_int8_t *); /* Decode Mixed PPP/CHDLC traffic */
void DecodeI4LRawIPPkt(struct pcap_pkthdr*, u_int8_t*); /* Decodes ISDN 4 linux packets coming in raw on layer 2, like PPP. */
void DecodeI4LCiscoIPPkt(struct pcap_pkthdr*, u_int8_t*); /*  Decodes packets coming in raw on layer 2, like PPP. */
void DecodePppPktEncapsulated( u_int8_t *,const u_int32_t); /* Decode PPP traffic (RFC1661 framing). */
void DecodeEthLoopback(u_int8_t *, u_int32_t);  /* Decode EthLoopback packet */
void DecodeEAP(u_int8_t *, const u_int32_t); /* Decode Extensible Authentication Protocol */
void DecodeEapolKey(u_int8_t *, u_int32_t);
void DecodeEapol(u_int8_t *, u_int32_t);
void DecodeLLC(u_int8_t *, const u_int32_t,struct pcap_pkthdr *); /* Decode LLC */
void DecodeSNAP(u_int8_t *, const u_int32_t,struct pcap_pkthdr *); /* Decode SNAP */
void DecodePPPoE(u_int8_t * , const u_int32_t ); /* Decode PPP over ethernet packets */
void DecodeEncPkt(struct pcap_pkthdr *, u_int8_t *); /* Decode Encapsulated VPN Packet */
void DecodeARP(void); /* Decode ARP */
void DecodeReverseARP(void); /* Decode Reverse ARP */
void DecodeIP(u_int8_t *, const u_int32_t); /* Decode the IP network layer */
void DecodeIPV6(u_int8_t *, u_int32_t,struct pcap_pkthdr *); /* IP Version 6 */
void DecodeVlan(u_int8_t *, const u_int32_t,struct pcap_pkthdr *); /* Decode Vlan traffic*/
void DecodeIPX(u_int8_t *, u_int32_t); /* Decode IPX NetWare protocol*/
void DecodeICMP(u_int8_t *, const u_int32_t, IPHdr *); /* Decode the ICMP transport layer */
void DecodeTCP(u_int8_t * ,const u_int32_t,IPHdr *); /* Decode the TCP transport layer */
void DecodeUDP(u_int8_t *,const u_int32_t,IPHdr *); /* Decode the UDP transport layer */
void DecodeGRE(u_int8_t *, u_int32_t,IPHdr *);/*  Decode Generic Routing Encapsulation Protocol */
int get_device_info(void); /* Get the interface device list */
void PrintPorts(u_int16_t,u_int16_t,char); /* print source and destination ports */
void printResolvedIP(char *); /* resolve IP in hostname and print it */
void printReverseDNSerror(int); /* print possible Reverse DNS error */
int CountLinesInFile(char *); /* count lines in file */
#ifndef HAVE_HCREATE_R
void InitHashTable(char * ,char * ); /* open file  parse it and create a hash table for each line */
#else
void InitHashTable(char * ,struct hsearch_data *);
#endif
void ShowProgramName(void); /* display program name */
void ShowAuthorInfo(void); /* display author name and other info */
void ParseCmdLine(int , char * *); /* Parse command line args */
void CleanExit(int); /* Clean up misc file handles,pcap and such and exit */
void SigTermHandler(int); /* Signal Handlers for SIGTERM */
void SigIntHandler(int); /* Signal Handlers for SIGINT */
void SigQuitHandler(int); /* Signal Handlers for SIGQUIT */
void SigWinChHandler(int); /* handler for window size change */

#define PACKETS_READ_TIMEOUT 500 /* used in the pcap lib */



