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


#include "llc.h"
#include "ip.h"
#include "snif.h" /* function names definitions */

#include "wifi.h"



extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */





/*
 * Function: DecodeIEEE80211Pkt( struct pcap_pkthdr*, 
 *                               u_int8_t*)
 *
 * Purpose: Decode those fun loving wireless LAN packets, one at a time!
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeIEEE80211Pkt(struct pcap_pkthdr * pkthdr, 
			u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */

    WifiHdr * ptr_wifi_hdr; 

    u_int16_t frame_control;
    
    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(BUFSIZ < pkt_len)
        pkt_len = cap_len;

    if (dump_link_layer) { 

      printf("WIFI ");

    }

    /* do a little validation */
    if(pkthdr->caplen < MINIMAL_IEEE80211_HEADER_LEN)
    {

      printf("Captured data length < IEEE 802.11 header length! (%d bytes)\n", pkthdr->caplen);

      return;
    }

    /* lay the wireless structure over the packet data */
    ptr_wifi_hdr = (WifiHdr *) pkt;

    frame_control = ptr_wifi_hdr->frame_control;
    
    if (dump_link_layer) { 
       
       /*
	*  Address Field Description
	*
	*  To DS  | From DS | Address 1 | Address 2 | Address 3 | Address 4
	*    0    |  0      |  DA       | SA        | BSSID     | N/A
	*    0    |  1      |  DA       | BSSID     | SA        | N/A
	*    1    |  0      |  BSSID    | SA        | DA        | N/A
	*    1    |  1      |  RA       | TA        | DA        | SA
	*/

       
      if (!TO_DS(frame_control) && !FROM_DS(frame_control)) {
	printf("%X --(%X)--> %X\n",
	       *ptr_wifi_hdr->addr2, *ptr_wifi_hdr->addr3, 
	       *ptr_wifi_hdr->addr1);
      }
      else if (!TO_DS(frame_control) && FROM_DS(frame_control)) {
	printf("%X -- %X --> %X\n",
	       *ptr_wifi_hdr->addr3, *ptr_wifi_hdr->addr2, 
	       *ptr_wifi_hdr->addr1);
      }
      else if (TO_DS(frame_control) && !FROM_DS(frame_control)) {
	printf("%X -- %X --> %X\n",
	       *ptr_wifi_hdr->addr2, *ptr_wifi_hdr->addr1, 
	       *ptr_wifi_hdr->addr3);
      }
      else if (TO_DS(frame_control) && FROM_DS(frame_control)) {
	 printf("%X -- %X -- %X --> %X\n",
	      *ptr_wifi_hdr->addr4, *ptr_wifi_hdr->addr2, 
                *ptr_wifi_hdr->addr1, *ptr_wifi_hdr->addr3);
      }
    }

    /* determine frame type */
    switch(ptr_wifi_hdr->frame_control & 0x00ff)
      {
        /* management frames */
      case WLAN_TYPE_MGMT_ASREQ:
      case WLAN_TYPE_MGMT_ASRES:
      case WLAN_TYPE_MGMT_REREQ:
      case WLAN_TYPE_MGMT_RERES:
      case WLAN_TYPE_MGMT_PRREQ:
      case WLAN_TYPE_MGMT_PRRES:
      case WLAN_TYPE_MGMT_BEACON:
      case WLAN_TYPE_MGMT_ATIM:
      case WLAN_TYPE_MGMT_DIS:
      case WLAN_TYPE_MGMT_AUTH:
      case WLAN_TYPE_MGMT_DEAUTH:
	
	if (dump_link_layer && verb) {
	  printf("Management frame\n");
	}
	
	break;
	
	/* Control frames */
      case WLAN_TYPE_CONT_PS:
      case WLAN_TYPE_CONT_RTS:
      case WLAN_TYPE_CONT_CTS:
      case WLAN_TYPE_CONT_ACK:
      case WLAN_TYPE_CONT_CFE:
      case WLAN_TYPE_CONT_CFACK:
	
	if (dump_link_layer && verb) {
	  printf("Control frame\n");
	}

	break;
	/* Data packets without data */
      case WLAN_TYPE_DATA_NULL:
      case WLAN_TYPE_DATA_CFACK:
      case WLAN_TYPE_DATA_CFPL:
      case WLAN_TYPE_DATA_ACKPL:
	
	if (dump_link_layer && verb) {
	  printf("Data frame without data\n");
	}
	
	break;
	
      case WLAN_TYPE_DATA_DTCFACK:
      case WLAN_TYPE_DATA_DTCFPL:
      case WLAN_TYPE_DATA_DTACKPL:
      case WLAN_TYPE_DATA_DATA:
            
	if (dump_link_layer && verb) {
	  printf("Data frame\n");
	}
	
	if(cap_len < IEEE802_11_DATA_HDR_LEN + sizeof(LLCHdr))  {
	  printf("Not enough data for WLan+LLC header\n");
	  printf("Dropping bad packet\n");             
	  return;
	}
	
	DecodeLLC(pkt + sizeof(WifiHdr),cap_len - sizeof(WifiHdr),pkthdr);
          
	break;
      
      default:
	printf("Unknown frame type\n");
	break;
    }

    return;
}
