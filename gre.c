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


#include <pcap.h>

#include <netinet/in.h>


/* needed for GRE, GRE packet encapsulated in IP packet sometimes */
#include "ip.h" 

#include "gre.h"

/*
 * Function: DecodeGRE(u_int8_t *, u_int32_t,IPHdr *)
 *
 * Purpose: Well, it doesn't do much of anything right now...
 *          Decode Generic Routing Encapsulation Protocol
 *          This will decode normal GRE and PPTP GRE.
 * as i do not care about GRE packet,just check header length
 * for now, will do better when i have more time....
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 * Notes: see RFCs 1701, 2784 and 2637
 *
 */
void DecodeGRE(u_int8_t *pkt, u_int32_t len,IPHdr * iptr) {

  if (len < GRE_HEADER_LEN)
    
    {
      
      printf("GRE header truncated! (%d bytes)\n", len);
      printf("minimum GRE header should be %d bytes length\n",GRE_HEADER_LEN); 
      
      return;

    }
  
  printf("GRE packet\n");

  return;

}


