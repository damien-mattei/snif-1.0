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

#include <sys/socket.h> /* needed for inet_ntoa */
#include <netinet/in.h> /* needed for inet_ntoa */
#include <arpa/inet.h>  /* needed for inet_ntoa */

#include "terminal.h" /* escape sequences for color,... */

#include "color.h" /* describe color and protocols */

#include "ip.h"

#include "snif.h" /* function names definitions */



extern int send_esc; /* send escape sequence to terminal
		      * enable color and bold text
		      */

extern int verb; /* verbose level
		  *  1:   verbose
		  *  0:   normal
		  * -1:   quiet
		  */

extern int resolv_ip; /* resolve or not IP address in hostname */



/* decoding of copied flag,class,option number */
void decodeIpOptionType(u_int8_t type) {

	  if ( COPIED_FLAG( type ) ) {
	    printf("  Copied Flag: copied (option is copied into all fragments on fragmentation)\n");
	  }
	  else {
	    printf("  Copied Flag: NOT copied\n");
	  }
	  
	  switch OPTION_CLASS( type )
	    {
	    case 0:
	      printf("  Option class: control\n");
	      break;
	    case 1:
	    case 3:
	      printf("  Option class: reserved for future use\n");
	      break;
	    case 2:
	      printf("  Option class: debugging and measurement\n");
	      break;
	    default:
	      break;
	    }
	  
	  if (verb > 0) {
	    printf("  Option number: %i\n",OPTION_NUMBER( type ));
	  }

}


/*
 * Function: DecodeIP(u_int8_t *, const u_int32_t)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *           
 *
 * Returns: void function
 */
void DecodeIP(u_int8_t * pkt, const u_int32_t len) {

  IPHdr * iptr;

  u_int32_t ip_len;       /* length from the start of the ip hdr to the
			   * pkt end */
  u_int32_t hlen;             /* ip header length */
  u_int16_t csum;             /* checksum */
  u_int16_t frag_offset;  /* fragment offset number */
  u_int8_t mf;            /* more fragments flag */
  u_int8_t df;            /* don't fragment flag */
  u_int8_t rf;                  /* IP reserved bit */
  u_int8_t ipver;           /* IP protocol version */
  u_int32_t ip_options_len; /* length of IP options */
  u_int8_t *option_ptr;     /* ptr to current option */
  u_int32_t opt_count = 0; /* what option are we processing right now */
  u_int8_t type; /* option type */
  u_int8_t length; /* option length */
  char done; /* done processing options */
  u_int8_t *end_ptr; /* pointer on the end of options */  
  u_int8_t byte_skip; /* number of byte of one option to skip to reach next option */
  u_int8_t pointer; /* pointer into the route data */
  u_int8_t *ptr_ip; /* pointer to IP router */
  u_int8_t *end_record; /* end of records */
  u_int8_t *ptr_record; /* pointer to record */
  u_int16_t stream_id; /* stream identifier */
  u_int16_t local_ptr; /* pointer for Loose and Strict Source routing IP address */

  if (send_esc) {
    SETCOLOR(IP_COLOR);
  }

  /* lay the IP struct over the raw data */
  iptr = (IPHdr *) pkt;
  
    
  /* do a little validation */
  if (len < IP_HEADER_LEN_MINI) {
    
    printf("IP header truncated! (%d bytes)\n", len);
    printf("minimum IP header should be %d bytes length\n",IP_HEADER_LEN_MINI); 
    
    return;
  }

  /* compute IP version */
  ipver = IP_VER(iptr);

  /*
   * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
   * So we are just ignoring non IP datagrams
   */
    if(ipver != 4) {
            printf("Not IPv4 datagram! ([ver: 0x%x][len: 0x%x])\n", 
                         ipver, iptr->ip_len);
	    return;
    }


    /******************************/
    /*                            */
    /* set the IP datagram length */
    ip_len = ntohs(iptr->ip_len);
    /*                            */
    /* set the IP header length   */
    hlen = IP_HLEN(iptr) << 2;
    /*                            */
    /******************************/


    /* header length sanity check */
    if(hlen < IP_HEADER_LEN_MINI)    {
      printf("Bogus IP header length of %i bytes\n", 
                         hlen);
        
        return;
    }
    
     if (ip_len != len) {
        if (ip_len > len) {
	  printf("IP Len field is %d bytes bigger than captured length.\n   (ip.len: %d, cap.len: %d)\n",
		 ip_len - len, ip_len, len);
	  ip_len = len;
        }
        else {
	  printf("IP Len field is %d bytes smaller than captured length.\n    (ip.len: %d, cap.len: %d)\n",
		 len - ip_len, ip_len, len);
	  
	}
     }
    
    if(ip_len < hlen) {
      printf("IP dgm len (%d bytes) < IP hdr "
	     "len (%d bytes), packet discarded\n", ip_len, hlen);
      
      return;
    }

   
    /* routers drop packets with bad IP checksums, we don't really 
     * need to check them (should make this a command line/config
     * option
     * but if you snif on a hub before packet reach the router
     * this could be safe to check the sums
     */
    
    csum = in_chksum_ip((u_short *)iptr, hlen);

    
    if(csum) {
      printf("Bad IP checksum\n");
      return;
    }
    else {
      if (verb > 0) {
	printf("IP Checksum: OK\n");
      }
    }
    
    /* set the remaining packet length */
    ip_len -= hlen;
    
    printf("IP ");
     
    if (send_esc) {
      SETATTRIB( BRIGHT );
      printf("%s",inet_ntoa(iptr->ip_src));
      NORMALMODE();
      SETCOLOR( IP_COLOR );
      if (resolv_ip) {
	printResolvedIP((char*)&(iptr->ip_src));
      }
      printf(" > ");
      SETATTRIB( BRIGHT );
      printf("%s",inet_ntoa(iptr->ip_dst));
      NORMALMODE();
      SETCOLOR( IP_COLOR);
      if (resolv_ip) {
	printResolvedIP((char*)&(iptr->ip_dst));
      }
      printf("\n");
    }
    else {
      printf("%s",inet_ntoa(iptr->ip_src));
      if (resolv_ip) {
	printResolvedIP((char*)&(iptr->ip_src));
      }
      printf(" > %s",inet_ntoa(iptr->ip_dst));
      if (resolv_ip) {
	printResolvedIP((char*)&(iptr->ip_dst));
      }
      printf("\n");
    }
     

    /* check for fragmented packets */
    frag_offset = ntohs(iptr->ip_off);

    /* 
     * get the values of the reserved, more 
     * fragments and don't fragment flags 
     */
    rf = (u_int8_t)((frag_offset & 0x8000) >> 15);
    df = (u_int8_t)((frag_offset & 0x4000) >> 14);
    mf = (u_int8_t)((frag_offset & 0x2000) >> 13);
      


    /* if in verbose mode we display those informations */
    if (verb > 0) {
      printf("IP version: %u   IP header length: %lu\n" 
	     ,ipver,(unsigned long)hlen);
      printf("TTL:%d TOS:0x%X ID:%d IP Datagram Length:%d",
	     iptr->ip_ttl,
	     iptr->ip_tos,
	     ntohs(iptr->ip_id),
	     ntohs(iptr->ip_len));  
      printf("Flags status:\n");
      printf("Reserved : %x , Don't Fragment : %x , More Fragment : %x\n",rf,df,mf);
    }
    else { /* default display */
      if (rf) { /* reserved flag */
	printf("Reserved flag set\n");
      }
      if (df) { /* don't fragment */
	printf("Don't fragment flag set\n");
      }
    }
    
    /* mask off the high bits in the fragment offset field */
    frag_offset &= 0x1FFF;
    
    if (mf) { /* more fragment */
      if (frag_offset) { /* not zero = it's not the first fragment */
	printf("Fragment  Offset: 0x%04X\n",frag_offset);
      }
      else { /* zero = first fragment */
	printf("First Fragment of Datagram\n");
      }
    }
    else { /* no more fragment */
      if (frag_offset) { /* there is an offset but the last one */
	printf("Last Fragment (Offset: 0x%04X)\n",frag_offset);
      }
      else { /* no offset = it's the first and the last = whole datagram */
	printf("Datagram\n");
      }
    }
    
    /* test for IP options */
    if (hlen > IP_HEADER_LEN_MINI) {
      printf("\nDecoding Options:\n\n");
      
      ip_options_len = hlen - IP_HEADER_LEN_MINI;
      option_ptr = pkt + IP_HEADER_LEN_MINI; /* start */
      end_ptr = option_ptr + ip_options_len; /* end */
      done = 0;
      while((option_ptr < end_ptr) && (opt_count < IP_OPTMAX)
	    && (done !=1)) {

	type = *option_ptr; 


	switch(type)  {

	case IPOPT_RTRALT:

	  printf("\n  RTRALT.\n");
	  decodeIpOptionType(type);
	  byte_skip = 1; /* we have a single byte option */

	  break;

	case IPOPT_NOP: /* No OPeration */

	  printf("\n  No Operation.\n");
	  decodeIpOptionType(type);
	  byte_skip = 1; /* we have a single byte option */

	  break;

	case IPOPT_EOL: /* End of Option List */

	  printf("\n  End of Option List.\n");
	  decodeIpOptionType(type);
	  byte_skip = 1; /* we have a single byte option */
	  /* if we hit an EOL, we're done */
	  done = 1;

	  break;

	case IPOPT_RR:

	  printf("\n  Record Route.\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  pointer = *(option_ptr + 2);
	  if (pointer < 3) { /* problem
			      * no space for a single record */
	    printf("    Pointer little than 3: no valid record.\n");
	  }
	  else {
	    ptr_ip = option_ptr + 3; /* 3 bytes (type,length,pointer) */
	    /* end_record = option_ptr + pointer; */ /* end of records */
	    end_record = option_ptr + length;
	    while ((ptr_ip + 1) < end_record) { /* still in valid record zone */
	      /* print IP */
	      printf("    %d.%d.%d.%d\n",*ptr_ip,*(ptr_ip+1),*(ptr_ip+2),*(ptr_ip+3));
	      ptr_ip += 4; /* 4 bytes: size of an IP address */
	    }
	  }
	  byte_skip = length;

	  break;
	  
	case IPOPT_TS: {

	  u_int8_t ovf_flag; /* overflow & flag (4 bits) in timestamp option */
	  u_int8_t overflow;
	  u_int8_t flag;
	  u_int32_t timestamp=0; /* Internet Timestamp */

	  printf("\n  Internet Timestamp.\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  pointer = *(option_ptr + 2);
	  ovf_flag = *(option_ptr + 3);
	  overflow = ovf_flag >> 4;
	  if (overflow)
	    printf("    %d IP modules that cannot register timestamps due to lack of space.\n",overflow);
	  if (pointer < 4) { /* problem
			      * no space for a single record */
	    printf("    Pointer little than 4: no valid record.\n");
	  }
	  else {
	    ptr_record = option_ptr + 4; /* 4 bytes (type,length,pointer,overflow-flag) */
	    /* end_record = option_ptr + pointer; */ /* end of records */
	    end_record = option_ptr + length;
	    flag = ovf_flag & 0x0f;

	    switch (flag) {

	    case TSONLY:

	      while ((ptr_record + 1) < end_record) { /* still in valid record zone */
		/* printf("%02X.%02X.%02X.%02X|%02X.%02X.%02X.%02X\n",*ptr_record,*(ptr_record+1),*(ptr_record+2),*(ptr_record+3),*(ptr_record+4),*(ptr_record+5),*(ptr_record+6),*(ptr_record+7)); */
		/* timestamp = ntohl(*ptr_record); */
		if ((*ptr_record) & 0x80) {
		  printf("    non-standard value ");
		   (*ptr_record) &= 0x7F; /* clear highest bit */
		}
		timestamp = ((u_int32_t) (*ptr_record) << 24)
		  | ((u_int32_t) (*(ptr_record+1)) << 16)
		  | ((u_int32_t) (*(ptr_record+2)) << 8)
		  | ((u_int32_t) (*(ptr_record+3)));
		printf("    %d\n",timestamp); /* print timestamp */
		/* printf("ptr_record:%d\t end_record:%d\n",ptr_record,end_record); */
		ptr_record += 4; /* 4 bytes: size of internet timestamp */
	      }

	      break;

	    case TSANDADDR:
	    case TSPRESPEC:

	      while ((ptr_record + 1) < end_record) { /* still in valid record zone */
		/* print IP */
		/* printf("%02X.%02X.%02X.%02X|%02X.%02X.%02X.%02X\n",*ptr_record,*(ptr_record+1),*(ptr_record+2),*(ptr_record+3),*(ptr_record+4),*(ptr_record+5),*(ptr_record+6),*(ptr_record+7)); */
		printf("    %d.%d.%d.%d\t",*ptr_record,*(ptr_record+1),*(ptr_record+2),*(ptr_record+3));
		/* printf("ptr_record:%d\t end_record:%d\n",ptr_record,end_record); */
		ptr_record += 4; /* 4 bytes: size of an IP address */
		if ((*ptr_record) & 0x80) {
		  printf("    non-standard value ");
		   (*ptr_record) &= 0x7F; /* clear highest bit */
		}
		/* timestamp = ntohl(*ptr_record); */
		timestamp = ((u_int32_t) (*ptr_record) << 24)
		  | ((u_int32_t) (*(ptr_record+1)) << 16)
		  | ((u_int32_t) (*(ptr_record+2)) << 8)
		  | ((u_int32_t) (*(ptr_record+3)));
		
		printf("    %d\n",timestamp); /* print timestamp */
		ptr_record += 4; /* 4 bytes: size of internet timestamp */
	      }

	      break;

	    default:

	      printf("    Unknown flag.\n");
	      decodeIpOptionType(type);

	      break;

	    }
	  }
	  byte_skip = length;
	}
	  break;
	  
	case IPOPT_SECURITY:

	  printf("\n  Security.\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  byte_skip = length;

	  break;

	  /* Loose Source Record route and Strict Source Record Route are not transmitted by routers, checked with tcpdump : */
	  /* tcpdump -vvv '(ip[20] & 0x83 == 0x83) && (ip[0] & 0xf != 5)' and did not get any result during one night on a megabit network */
	  /* i'm not a lazy coder but i think that implementing
	   * case for things that will never occur is a waste of time */

	  /* to be coded,rationale: the sending of a ping with routiong option can be
	   * analyzed with a frame decoder
	   *  example:


ping -n -c 1 192.54.174.43 192.54.174.250 192.54.174.43 192.54.174.250 192.54.174.43 192.54.174.250 192.54.174.43 192.54.174.250 192.54.174.43 192.54.174.250

result with packet sniffer:

ETHERNET 0:19:b9:1a:be:65 > 0:1:30:dc:4f:0
unknown ethernet card > Extreme Networks ethernet card
IP 192.54.176.17 > 192.54.174.43
Don't fragment flag set
Datagram

Decoding Options:


  No Operation.
  Copied Flag: NOT copied
  Option class: control

  Loose Source Routing.
  Copied Flag: copied (option is copied into all fragments on fragmentation)
  Option class: control

    192.54.174.250
    192.54.174.43 (next)
    192.54.174.250
    192.54.174.43
    192.54.174.250
    192.54.174.43
    192.54.174.250
    192.54.174.43
    192.54.174.250
ICMP Echo Request
ICMP Checksum: OK
ICMP type: 8   code: 0

	   */

	  /*

	  RFC 791:

      Loose Source and Record Route

        +--------+--------+--------+---------//--------+
        |10000011| length | pointer|     route data    |
        +--------+--------+--------+---------//--------+
         Type=131

        The loose source and record route (LSRR) option provides a means
        for the source of an internet datagram to supply routing
        information to be used by the gateways in forwarding the
        datagram to the destination, and to record the route
        information.

        The option begins with the option type code.  The second octet
        is the option length which includes the option type code and the
        length octet, the pointer octet, and length-3 octets of route
        data.  The third octet is the pointer into the route data
        indicating the octet which begins the next source address to be
        processed.  The pointer is relative to this option, and the
        smallest legal value for the pointer is 4.

        A route data is composed of a series of internet addresses.
        Each internet address is 32 bits or 4 octets.  If the pointer is
        greater than the length, the source route is empty (and the
        recorded route full) and the routing is to be based on the
        destination address field.


[Page 18]                                                               


September 1981                                                          
                                                       Internet Protocol
                                                           Specification



        If the address in destination address field has been reached and
        the pointer is not greater than the length, the next address in
        the source route replaces the address in the destination address
        field, and the recorded route address replaces the source
        address just used, and pointer is increased by four.

        The recorded route address is the internet module's own internet
        address as known in the environment into which this datagram is
        being forwarded.

        This procedure of replacing the source route with the recorded
        route (though it is in the reverse of the order it must be in to
        be used as a source route) means the option (and the IP header
        as a whole) remains a constant length as the datagram progresses
        through the internet.

        This option is a loose source route because the gateway or host
        IP is allowed to use any route of any number of other
        intermediate gateways to reach the next address in the route.

        Must be copied on fragmentation.  Appears at most once in a
        datagram.

	  */

	    
	case IPOPT_LSRR:
	case IPOPT_LSRR_E:

	  printf("\n  Loose Source Routing.\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  pointer = *(option_ptr + 2);
	  if (pointer < 3) { /* problem
			      * no space for a single record */

	    printf("    Pointer little than 3: no valid record.\n");

	  }

	  else {

	    printf("\n");
	    local_ptr = 0; /* offset in the route data */
	    ptr_ip = option_ptr + 3 + local_ptr;  /* 3 bytes (type,length,pointer) */
	    /* end_record = option_ptr + pointer; */ /* end of records */
	    end_record = option_ptr + length;

	    while ((ptr_ip + 1) < end_record) { /* still in valid record zone */
	      
	      /* print IP */
	      printf("    %d.%d.%d.%d",*ptr_ip,*(ptr_ip+1),*(ptr_ip+2),*(ptr_ip+3));
	      
	      /* show pointed router */
	      if (local_ptr == pointer) {
		printf(" (next)\n");
	      }
	      else {
		printf("\n");
	      }
	      /* printf("%d %d\n",local_ptr,pointer); */
	      local_ptr += 4; /* 4 bytes: size of an IP address */

	      ptr_ip = option_ptr + 3 +local_ptr; /* 3 bytes (type,length,pointer) */

	    }
	  }

	  byte_skip = length;

	  break;

	  /*
	    
	  RFC 791:

	  
      Strict Source and Record Route

        +--------+--------+--------+---------//--------+
        |10001001| length | pointer|     route data    |
        +--------+--------+--------+---------//--------+
         Type=137

        The strict source and record route (SSRR) option provides a
        means for the source of an internet datagram to supply routing
        information to be used by the gateways in forwarding the
        datagram to the destination, and to record the route
        information.

        The option begins with the option type code.  The second octet
        is the option length which includes the option type code and the
        length octet, the pointer octet, and length-3 octets of route
        data.  The third octet is the pointer into the route data
        indicating the octet which begins the next source address to be
        processed.  The pointer is relative to this option, and the
        smallest legal value for the pointer is 4.

        A route data is composed of a series of internet addresses.
        Each internet address is 32 bits or 4 octets.  If the pointer is
        greater than the length, the source route is empty (and the



                                                               [Page 19]


                                                          September 1981
Internet Protocol
Specification



        recorded route full) and the routing is to be based on the
        destination address field.

        If the address in destination address field has been reached and
        the pointer is not greater than the length, the next address in
        the source route replaces the address in the destination address
        field, and the recorded route address replaces the source
        address just used, and pointer is increased by four.

        The recorded route address is the internet module's own internet
        address as known in the environment into which this datagram is
        being forwarded.

        This procedure of replacing the source route with the recorded
        route (though it is in the reverse of the order it must be in to
        be used as a source route) means the option (and the IP header
        as a whole) remains a constant length as the datagram progresses
        through the internet.

        This option is a strict source route because the gateway or host
        IP must send the datagram directly to the next address in the
        source route through only the directly connected network
        indicated in the next address to reach the next gateway or host
        specified in the route.

        Must be copied on fragmentation.  Appears at most once in a
        datagram.


	  */

	case IPOPT_SSRR:

	  printf("\n  Strict Source Routing.\n");
	  decodeIpOptionType(type);
	  length = *(option_ptr + 1);
	  pointer = *(option_ptr + 2);

	  if (pointer < 3) { /* problem
			      * no space for a single record */

	    printf("    Pointer little than 3: no valid record.\n");

	  }

	  else {

	    printf("\n");
	    local_ptr = 0; /* offset in the route data */
	    ptr_ip = option_ptr + 3 + local_ptr;  /* 3 bytes (type,length,pointer) */
	    /* end_record = option_ptr + pointer; */ /* end of records */
	    end_record = option_ptr + length;

	    while ((ptr_ip + 1) < end_record) { /* still in valid record zone */
	      
	      /* print IP */
	      printf("    %d.%d.%d.%d",*ptr_ip,*(ptr_ip+1),*(ptr_ip+2),*(ptr_ip+3));
	      
	      /* show pointed router */
	      if (local_ptr == pointer) {
		printf(" (next)\n");
	      }
	      else {
		printf("\n");
	      }
	      /* printf("%d %d\n",local_ptr,pointer); */
	      local_ptr += 4; /* 4 bytes: size of an IP address */

	      ptr_ip = option_ptr + 3 +local_ptr; /* 3 bytes (type,length,pointer) */

	    }
	    
	  }

	  byte_skip = length;

	  break;
	
	case IPOPT_SATID:

	  printf("\n  Stream Identifier.\n");
	  stream_id = *(option_ptr + 2);
	  printf("Stream ID = %i\n",stream_id);
	  length = *(option_ptr + 1);
	  byte_skip = length;

	  break;

	default:

	  printf("\n  Unknown option.\n");
	  length = *(option_ptr + 1);
	  byte_skip = length;

	  break;
	}
	
	opt_count++;
	
	option_ptr += byte_skip;

      } /* end of while */
      
    }

    switch(iptr->ip_proto)

      {

      case IPPROTO_TCP:

	DecodeTCP(pkt + hlen, ip_len, iptr);
	return;

      case IPPROTO_UDP:

	DecodeUDP(pkt + hlen, ip_len, iptr);
	return;

      case IPPROTO_ICMP:
      
	DecodeICMP(pkt + hlen, ip_len, iptr);
	return;

      case IPPROTO_GRE:
        
	DecodeGRE(pkt + hlen, ip_len, iptr);
	return;

      default:
	printf("Unknown network protocol: code %d\n",iptr->ip_proto);
	return;
      }
    
    return;
}

