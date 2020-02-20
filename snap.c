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

#include "snap.h"
#include "ethernet.h"

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */





/*
 * Function: DecodeSNAP(u_int8_t*, const u_int32_t,struct pcap_pkthdr *)
 *
 * Purpose: Decode Sub Network Access Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeSNAP(u_int8_t * pkt, const u_int32_t len,struct pcap_pkthdr * pkthdr)
{

  SNAPHdr * snap_hdr_ptr;
  
  u_int32_t dataoff = sizeof(SNAPHdr);

  if(len < dataoff)
    {
      printf("Captured data length < SNAP header length! (%d < %d bytes)\n", len, dataoff);
      return;
    }
  
  snap_hdr_ptr = (SNAPHdr *) pkt;
  
  if (dump_link_layer) { 

    printf( "SNAP  Organization code: %X%X%X EtherType: %X\n",
            snap_hdr_ptr->orgcode[0],snap_hdr_ptr->orgcode[1],snap_hdr_ptr->orgcode[2]
	    , snap_hdr_ptr->ethertype);
      	         
    }

   switch(htons(snap_hdr_ptr->ethertype))
    {
        case ETHERNET_TYPE_IP:
	  DecodeIP(pkt + dataoff, len - dataoff);
            return;

        case ETHERNET_TYPE_ARP:
	  DecodeARP();
	  return;
        case ETHERNET_TYPE_REVARP:
	  DecodeReverseARP();
	  return;

        case ETHERNET_TYPE_8021Q:
	  DecodeVlan(pkt + dataoff, len - dataoff,pkthdr);
	  return; 

        case ETHERNET_TYPE_EAPOL:
	  DecodeEapol(pkt + dataoff,len - dataoff);
	  return;

        case ETHERNET_TYPE_IPV6:
          DecodeIPV6(pkt + dataoff,len - dataoff,pkthdr);
	  return;

        default:
            printf( "Unknown network protocol: code %d\n",
                        htons(snap_hdr_ptr->ethertype));
	    return;
    }

   return;
}



