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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* hcreate_r works only when _GNU_SOURCE defined */
#ifdef HAVE_HCREATE_R
#define _GNU_SOURCE
#endif


#include <pcap.h>

#include <search.h> /* added for hash tables */

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

#ifdef HAVE_NETINET_ETHER_H
#include <netinet/ether.h> /* needed for ether_ntoa */
#endif

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"
#include "snif.h" /* function names definitions */

#include "ethernet.h"

extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */


extern int show_eth_vend; /* show ethernet vendor codes */

extern char * vendsrc; /* ethernet vendor code of source address */
extern char * venddst; /* ethernet vendor code of destination address */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern struct hsearch_data htab_ethernet; /* hash table for ethernet */






/*
 * Function: DecodeEthPkt( struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments:
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeEthPkt(struct pcap_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */

    EtherHdr * eptr;

#ifndef  HAVE_ETHER_NTOA
    u_char *ptr; /* printing out hardware header info */
    
    int i; 
    
#endif

    /* char etherhost[255]; */ /* hostname in ARP cache */

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

   
    /* do a little validation */
    if(cap_len < ETHER_HDR_LEN)
      {

	printf("ETHERNET\n");
	printf("Captured data length < Ethernet header length!\n (%d bytes < %d bytes)\n", cap_len, ETHER_HDR_LEN);
	return;
      }
    
    /* lay the ethernet structure over the packet data */
    eptr = (EtherHdr *) pkt;

  
    if (dump_link_layer) { 

      printf("ETHERNET ");

      /* THANK YOU RICHARD STEVENS!!! */

        
      if (send_esc) { /* print that with enligtments ! */

	SETATTRIB( BRIGHT );
	

#ifdef  HAVE_ETHER_NTOA

	printf("%s",ether_ntoa((struct ether_addr *)eptr->ether_src));

#else

	/* print source MAC address */
	ptr = eptr->ether_src;
	i = ETHER_ADDR_LEN;	
	do {
	  printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);

#endif

	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR );

	/* looks in ARP cache for IP */
	/* see man page , unfortunally /etc/ethers doesn't exist */ 
	/* if (!(ether_ntohost(etherhost,eptr->ether_src)))  */
/* 	  printf(" (%s)",etherhost); */

	printf(" > ");
	SETATTRIB( BRIGHT );
	

#ifdef  HAVE_ETHER_NTOA

	printf("%s",ether_ntoa((struct ether_addr *)eptr->ether_dst));

#else

	/* print destination MAC address */
	ptr = eptr->ether_dst;
	i = ETHER_ADDR_LEN;
    	do {
	  printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);

#endif
      
	NORMALMODE();
	SETCOLOR( DATA_LINK_LAYER_COLOR);
	
	/* if (!(ether_ntohost(etherhost,eptr->ether_dst)))  */
/* 	  printf(" (%s)",etherhost); */

	printf("\n");
      }
      else { /* no color, no bright...  too bad! */

#ifdef  HAVE_ETHER_NTOA

	printf("%s",ether_ntoa((struct ether_addr *)eptr->ether_src));

#else

	ptr = eptr->ether_src;
	i = ETHER_ADDR_LEN;	
	do {
	  printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);
#endif


	printf(" > ");


#ifdef  HAVE_ETHER_NTOA

	printf("%s",ether_ntoa((struct ether_addr *)eptr->ether_src));

#else

	ptr = eptr->ether_dst;
	i = ETHER_ADDR_LEN;
	do {
	  printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);

#endif
      
	printf("\n");
      }

      
#ifndef HAVE_HCREATE_R


      if (show_eth_vend) {
	if (send_esc) {
	  
	  ENTRY query,*result;
	  u_char * ptr_eth;
	  ptr_eth = eptr->ether_src;
	  SETATTRIB( BRIGHT );
	  /* check if broadcast */
	  if ((*ptr_eth == 0xff)
	      && (*(ptr_eth+1) ==  0xff)
	      && (*(ptr_eth+2) ==  0xff)
	      && (*(ptr_eth+3) ==  0xff)
	      && (*(ptr_eth+4) ==  0xff)
	      && (*(ptr_eth+5) ==  0xff)) {
	    printf("Broadcast addressing");
	  }
	  else {
	    
	    sprintf(vendsrc,"E%02X%02X%02X",*ptr_eth,*(ptr_eth+1),*(ptr_eth+2));
	    query.key = vendsrc;
	    result = hsearch(query, FIND);
	    
	    printf("%s ethernet card",
		   (char *) (result ? result->data : "unknown" ));
	    
	  }
	  NORMALMODE();
	  SETCOLOR( DATA_LINK_LAYER_COLOR );

	  printf(" > ");

	  ptr_eth = eptr->ether_dst;
	  SETATTRIB( BRIGHT );
	  /* check if broadcast */
	  if ((*ptr_eth == 0xff)
	      && (*(ptr_eth+1) ==  0xff)
	      && (*(ptr_eth+2) ==  0xff)
	      && (*(ptr_eth+3) ==  0xff)
	      && (*(ptr_eth+4) ==  0xff)
	      && (*(ptr_eth+5) ==  0xff)) {
	    printf("Broadcast addressing\n");
	  }
	  else {
	    
	    sprintf(venddst,"E%02X%02X%02X",*ptr_eth,*(ptr_eth+1),*(ptr_eth+2));
	    query.key = venddst;
	    result = hsearch(query, FIND);
	    
	    printf("%s ethernet card\n",
		   (char *) (result ? result->data : "unknown" ));
	    
	  }
	  NORMALMODE();
	  SETCOLOR( DATA_LINK_LAYER_COLOR);
	}
	else { /* no color */
	  
	  ENTRY query,*result;
	  u_char * ptr_eth;
	  ptr_eth = eptr->ether_src;
	  /* check if broadcast */
	  if ((*ptr_eth == 0xff)
	      && (*(ptr_eth+1) ==  0xff)
	      && (*(ptr_eth+2) ==  0xff)
	      && (*(ptr_eth+3) ==  0xff)
	      && (*(ptr_eth+4) ==  0xff)
	      && (*(ptr_eth+5) ==  0xff)) {
	    printf("Broadcast addressing");
	  }
	  else {
	    
	    sprintf(vendsrc,"E%02X%02X%02X",*ptr_eth,*(ptr_eth+1),*(ptr_eth+2));
	    query.key = vendsrc;
	    result = hsearch(query, FIND);
	    printf("%s ethernet card ",
		  (char *) (result ? result->data : "unknown" ));
	  }

	  printf(" > ");

	  ptr_eth = eptr->ether_dst;
	  /* check if broadcast */
	  if ((*ptr_eth == 0xff)
	      && (*(ptr_eth+1) ==  0xff)
	      && (*(ptr_eth+2) ==  0xff)
	      && (*(ptr_eth+3) ==  0xff)
	      && (*(ptr_eth+4) ==  0xff)
	      && (*(ptr_eth+5) ==  0xff)) {
	    printf("Broadcast addressing\n");
	  }
	  else {
	    
	    sprintf(venddst,"E%02X%02X%02X",*ptr_eth,*(ptr_eth+1),*(ptr_eth+2));
	    query.key = venddst;
	    result = hsearch(query, FIND);
	    printf("%s ethernet card\n",
		  (char *) ( result ? result->data : "unknown") );
	  }   
	}
      }

#else
     
      if (show_eth_vend) {
	if (send_esc) {
	  
	  ENTRY query,*result;
	  u_char * ptr_eth;
	  ptr_eth = eptr->ether_src;
	  SETATTRIB( BRIGHT );
	  /* check if broadcast */
	  if ((*ptr_eth == 0xff)
	      && (*(ptr_eth+1) ==  0xff)
	      && (*(ptr_eth+2) ==  0xff)
	      && (*(ptr_eth+3) ==  0xff)
	      && (*(ptr_eth+4) ==  0xff)
	      && (*(ptr_eth+5) ==  0xff)) {
	    printf("Broadcast addressing");
	  }
	  else {
	    int err;
	    sprintf(vendsrc,"%02X%02X%02X",*ptr_eth,*(ptr_eth+1),*(ptr_eth+2));
	    query.key = vendsrc;
	    err = hsearch_r(query, FIND, &result, &htab_ethernet );
	    
	    printf("%s ethernet card",
		   (char *) (err ? result->data : "unknown") );
	    
	  }
	  NORMALMODE();
	  SETCOLOR( DATA_LINK_LAYER_COLOR );

	  printf(" > ");

	  ptr_eth = eptr->ether_dst;
	  SETATTRIB( BRIGHT );
	  /* check if broadcast */
	  if ((*ptr_eth == 0xff)
	      && (*(ptr_eth+1) ==  0xff)
	      && (*(ptr_eth+2) ==  0xff)
	      && (*(ptr_eth+3) ==  0xff)
	      && (*(ptr_eth+4) ==  0xff)
	      && (*(ptr_eth+5) ==  0xff)) {
	    printf("Broadcast addressing\n");
	  }
	  else {
	    int err;
	    sprintf(venddst,"%02X%02X%02X",*ptr_eth,*(ptr_eth+1),*(ptr_eth+2));
	    query.key = venddst;
	    err = hsearch_r(query, FIND, &result, &htab_ethernet );
	    
	    printf("%s ethernet card\n",
		   (char *) (err ? result->data : "unknown") );
	    
	  }
	  NORMALMODE();
	  SETCOLOR( DATA_LINK_LAYER_COLOR);
	}
	else { /* no color */
	  
	  ENTRY query,*result;
	  u_char * ptr_eth;
	  ptr_eth = eptr->ether_src;
	  /* check if broadcast */
	  if ((*ptr_eth == 0xff)
	      && (*(ptr_eth+1) ==  0xff)
	      && (*(ptr_eth+2) ==  0xff)
	      && (*(ptr_eth+3) ==  0xff)
	      && (*(ptr_eth+4) ==  0xff)
	      && (*(ptr_eth+5) ==  0xff)) {
	    printf("Broadcast addressing");
	  }
	  else {
	    int err;
	    sprintf(vendsrc,"%02X%02X%02X",*ptr_eth,*(ptr_eth+1),*(ptr_eth+2));
	    query.key = vendsrc;
	    err = hsearch_r(query, FIND, &result, &htab_ethernet );
	    printf("%s ethernet card ",
		   (char *)(err ? result->data : "unknown") );
	  }

	  printf(" > ");

	  ptr_eth = eptr->ether_dst;
	  /* check if broadcast */
	  if ((*ptr_eth == 0xff)
	      && (*(ptr_eth+1) ==  0xff)
	      && (*(ptr_eth+2) ==  0xff)
	      && (*(ptr_eth+3) ==  0xff)
	      && (*(ptr_eth+4) ==  0xff)
	      && (*(ptr_eth+5) ==  0xff)) {
	    printf("Broadcast addressing\n");
	  }
	  else {
	    int err;
	    sprintf(venddst,"%02X%02X%02X",*ptr_eth,*(ptr_eth+1),*(ptr_eth+2));
	    query.key = venddst;
	    err = hsearch_r(query, FIND, &result, &htab_ethernet );
	    printf("%s ethernet card\n",
		   (char *)(err ? result->data : "unknown") );
	  }   
	}
      }

#endif

    }    
 

    /* grab out the network type */
    switch(ntohs(eptr->ether_type))

      {

      case ETHERNET_TYPE_PPPoE_DISC:
      case ETHERNET_TYPE_PPPoE_SESS:
	DecodePPPoE(pkt + ETHERNET_HEADER_LEN, 
		 cap_len - ETHERNET_HEADER_LEN);
	return;
	
      case ETHERNET_TYPE_IP:
	
	if (verb > 0) {
	  printf(
		 "IP datagram size calculated to be %lu bytes\n",
		 (unsigned long)(cap_len - ETHERNET_HEADER_LEN)
		 );
	}
	
	DecodeIP(pkt + ETHERNET_HEADER_LEN, 
		 cap_len - ETHERNET_HEADER_LEN);
	
	return;
	
      case ETHERNET_TYPE_ARP:
	DecodeARP();
	return;

      case ETHERNET_TYPE_REVARP:
	DecodeReverseARP();
	return;
	
      case ETHERNET_TYPE_IPV6:
	DecodeIPV6(pkt + ETHERNET_HEADER_LEN,
		   (cap_len - ETHERNET_HEADER_LEN), pkthdr);
	return;
	
      case ETHERNET_TYPE_IPX:
	
	  DecodeIPX(pkt + ETHERNET_HEADER_LEN,
	                     (cap_len - ETHERNET_HEADER_LEN));
	return;
	
      case ETHERNET_TYPE_LOOP:
	DecodeEthLoopback(pkt + ETHERNET_HEADER_LEN, 
			  (cap_len - ETHERNET_HEADER_LEN));
	return;

      case ETHERNET_TYPE_8021Q:
	DecodeVlan(pkt + ETHERNET_HEADER_LEN,
		   cap_len - ETHERNET_HEADER_LEN,pkthdr);
	return; 
	
      default:
	printf("Unknown network protocol: code %d\n",ntohs(eptr->ether_type));
	return;

      }


}
