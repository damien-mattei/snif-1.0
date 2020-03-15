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

#include "eap.h"


extern int dump_link_layer; /* dump network link layer info (ethernet address ,...) */







/*
 * Function: DecodeEAP(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode Extensible Authentication Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 * Returns: void function
 */
void DecodeEAP(u_int8_t * pkt, const u_int32_t len)
{
 
    if(len < sizeof(EAPHdr))
    {
 
      printf("Truncated packet\n");

      return;
    }
    if (((EAPHdr *)pkt)->code == EAP_CODE_REQUEST ||
            ((EAPHdr *)pkt)->code == EAP_CODE_RESPONSE) {
      
    }
    return;
}

/*
 * Function: DecodeEapolKey(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode 1x key setup
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEapolKey(u_int8_t * pkt, u_int32_t len)
{
   
    if(len < sizeof(EapolKey))
    {
      printf("Truncated packet\n");

      return;
    }

    return;  
}

/*
 * Function: DecodeEapol(u_int8_t *, u_int32_t)
 *
 * Purpose: Decode 802.1x eapol stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEapol(u_int8_t * pkt, u_int32_t len)
{
 
  if (dump_link_layer) { 

    printf( " EAP Packet!\n");
    
  }
    
    if(len < sizeof(EtherEapol))
    {
            printf("Truncated packet\n");

	    return;
    }
    if (((EtherEapol *)pkt)->eaptype == EAPOL_TYPE_EAP) {
        DecodeEAP(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol));
    }    
    else if(((EtherEapol *)pkt)->eaptype == EAPOL_TYPE_KEY) {
        DecodeEapolKey(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol));
    }
    return;
}
