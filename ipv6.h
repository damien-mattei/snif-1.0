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

#include "sfutil/sfxhash.h"

#define IP_PROTO_HOPOPTS    0
#define IP_PROTO_NONE       59
#define IP_PROTO_ROUTING    43
#define IP_PROTO_FRAGMENT   44
#define IP_PROTO_AH         51
#define IP_PROTO_DSTOPTS    60
#define IP_PROTO_ICMPV6     58
#define IP_PROTO_IPV6       41
#define IP_PROTO_IPIP       4

#define IPV6_FRAG_STR_ALERTED 1
#define IPV6_FRAG_NO_ALERT 0
#define IPV6_FRAG_ALERT 1
#define IPV6_FRAG_BAD_PKT 2
#define IPV6_MIN_TTL_EXCEEDED 3
#define IPV6_IS_NOT 4
#define IPV6_TRUNCATED_EXT 5
#define IPV6_TRUNCATED_FRAG 6
#define IPV6_TRUNCATED 7

#ifdef WORDS_BIGENDIAN
#define IP6F_OFF_MASK       0xfff8  /* mask out offset from _offlg */
#define IP6F_MORE_FRAG      0x0001  /* more-fragments flag */
#else   /* BYTE_ORDER == LITTLE_ENDIAN */
#define IP6F_OFF_MASK       0xf8ff  /* mask out offset from _offlg */
#define IP6F_MORE_FRAG      0x0100  /* more-fragments flag */
#endif



void BsdFragHashCleanup(void);
void BsdFragHashReset(void);
void BsdFragHashInit(int);
int CheckIPV6Frag(char *, u_int32_t,struct pcap_pkthdr *);


// que de redondances dans ces declarations !!!

typedef struct _IP6RawHdr
{
  union
  {
    struct _IP6HdrCtl
    {
      uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
				  20 bits flow-ID */
      uint16_t ip6_un1_plen;   /* payload length */
      uint8_t  ip6_un1_nxt;    /* next header */
      uint8_t  ip6_un1_hlim;   /* hop limit */
    } IP6HdrCtl;
    uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
  } IP6Ctl;
  
  struct in6_addr ip6_src;      /* source address */
  struct in6_addr ip6_dst;      /* destination address */
} IP6RawHdr;



struct ip6_hdr
{
  union
  {
    struct ip6_hdrctl
    {
      uint32_t ip6_un1_flow;   /* 4 bits version,
				  8 bits Traffic Class,
				  20 bits flow-ID */
      uint16_t ip6_un1_plen;   /* payload length */
      uint8_t  ip6_un1_nxt;    /* next header */
      uint8_t  ip6_un1_hlim;   /* hop limit */
    } ip6_un1;
    uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
  } ip6_ctlun;
  struct in6_addr ip6_src;      /* source address */
  struct in6_addr ip6_dst;      /* destination address */
};

#define IP6_HDR_LEN 40
#define IP_PROTO_HOPOPTS    0
#define IP_PROTO_NONE       59
#define IP_PROTO_ROUTING    43
#define IP_PROTO_FRAGMENT   44
#define IP_PROTO_AH         51
#define IP_PROTO_DSTOPTS    60
#define IP_PROTO_ICMPV6     58
#define IP_PROTO_IPV6       41
#define IP_PROTO_IPIP       4

#define ip6vfc   IP6Ctl.ip6_un2_vfc
#define ip6flow  IP6Ctl.IP6HdrCtl.ip6_un1_flow
#define ip6plen  IP6Ctl.IP6HdrCtl.ip6_un1_plen
#define ip6nxt   IP6Ctl.IP6HdrCtl.ip6_un1_nxt
#define ip6hlim  IP6Ctl.IP6HdrCtl.ip6_un1_hlim
#define ip6hops  IP6Ctl.IP6HdrCtl.ip6_un1_hlim


/* Fragment header */
typedef struct _IP6Frag
{
    uint8_t   ip6f_nxt;     /* next header */
    uint8_t   ip6f_reserved;    /* reserved field */
    uint16_t  ip6f_offlg;   /* offset, reserved, and flag */
    uint32_t  ip6f_ident;   /* identification */
} IP6Frag;



typedef struct _ipv6vfc_header_chain {
    u_int8_t        next_header;
    u_int8_t        length;
} ipv6_header_chain;

