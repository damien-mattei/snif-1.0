/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2007  Damien MATTEI <Damien.MATTEI@free.fr>

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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* hcreate_r works only when _GNU_SOURCE defined */
#ifdef HAVE_HCREATE_R
#define _GNU_SOURCE
#endif


#include <pcap.h>

#include <netinet/in.h>

#include <search.h> /* added for hash tables */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "ethernet.h"
#include "sll.h"

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */







#ifdef DLT_LINUX_SLL

/*
 * Function: DecodeLinuxSLLPkt(char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode those fun loving LinuxSLL (linux cooked sockets) 
 *          packets, one at a time!
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
 


void DecodeLinuxSLLPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* the length of the packet */
    u_int32_t cap_len;      /* caplen value */

    SLLHdr * sll_hdr_ptr;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(BUFSIZ < pkt_len)
        pkt_len = cap_len;

    if (dump_link_layer) { 

      printf("Linux cooked sockets\n");

    }

    /* do a little validation */
    if(pkthdr->caplen < SLL_HDR_LEN)
    {
     
           printf("Captured data length < SLL header length (your "
                         "libpcap is broken?)! (%d bytes)\n", pkthdr->caplen);
       
        return;
    }
    /* lay the ethernet structure over the packet data */
    sll_hdr_ptr = (SLLHdr *) pkt;
    
    /* grab out the network type */
    switch(ntohs(sll_hdr_ptr->sll_protocol))
      {
      case ETHERNET_TYPE_IP:
	
	DecodeIP(pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN);
	return;
	
      case ETHERNET_TYPE_ARP:
	DecodeARP();
	return;
      case ETHERNET_TYPE_REVARP:
	DecodeReverseARP();
	return;
	
      case ETHERNET_TYPE_IPV6:
	DecodeIPV6(pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), pkthdr);
	return;
	
      case ETHERNET_TYPE_IPX:
	DecodeIPX(pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN));
	return;
	
      case LINUX_SLL_P_802_3:
	printf("Linux SLL P 802.3 is not supported.\n");
	return;
	
      case LINUX_SLL_P_802_2:
	
	/* printf("Linux SLL P 802.2 is not supported.\n"); */
	return;

      case ETHERNET_TYPE_8021Q:
	DecodeVlan(pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN,pkthdr);
	return; 
	    
      default:
	
	printf( "Unknown network protocol: code %d\n",
		ntohs(sll_hdr_ptr->sll_protocol) );
	return;
      }
    
    return;
}

#endif






