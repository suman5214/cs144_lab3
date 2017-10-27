/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdlib.h>
#include <string.h>

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
struct sr_if* sr_get_interface_given_ip(struct sr_instance* sr, uint32_t ip)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(ip);
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
       if(if_walker->ip == ip)
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
}

void icmp_direct_echo_reply(struct sr_instance *sr,
  uint8_t *packet /* lent */,
  unsigned int len,
  char *interface /* lent */,
  sr_ethernet_hdr_t *eth_hdr,
  sr_ip_hdr_t *ipHdr,
  sr_icmp_hdr_t *icmpHdr)
{

int icmpOffset = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);

/* We don't have to look up the routing table for this one */
struct sr_if *myInterface = sr_get_interface(sr, interface);

icmpHdr->icmp_type = 0;
icmpHdr->icmp_code = 0;
icmpHdr->icmp_sum = icmp_cksum(icmpHdr, len - icmpOffset);

ipHdr->ip_dst = ipHdr->ip_src;
ipHdr->ip_src = myInterface->ip;
ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));

uint8_t *destAddr = malloc(ETHER_ADDR_LEN);
uint8_t *srcAddr = malloc(ETHER_ADDR_LEN);
memcpy(destAddr, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
memcpy(srcAddr, eth_hdr->ether_shost, ETHER_ADDR_LEN);

memcpy(eth_hdr->ether_dhost, srcAddr, ETHER_ADDR_LEN);
memcpy(eth_hdr->ether_shost, destAddr, ETHER_ADDR_LEN);

print_hdrs(packet, len);
sr_send_packet(sr, packet, len, interface);
}

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("** -> Received packet of length \n");
  print_hdr_eth(packet);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

  uint16_t pktType = ntohs(eth_hdr->ether_type);

  if (is_packet_valid(packet, len))
  {
    if (pktType == ethertype_arp)
    {
      sr_handle_arp_packet(sr, packet, len, interface);
    }
    else if (pktType == ethertype_ip)
    {
      sr_handle_ip_packet(sr, packet, len, interface);
    }
  }
} 

void sr_arp_request_send(struct sr_instance *sr, uint32_t ip){
  printf("$$$ -> Send ARP request.\n");

  int arpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *arpPacket = malloc(arpPacketLen);

  sr_ethernet_hdr_t *eth_hdr = (struct sr_ethernet_hdr *)arpPacket;
  memcpy(eth_hdr->ether_dhost, generate_ethernet_addr(255), ETHER_ADDR_LEN);

  struct sr_if *currIf = sr->if_list;
  uint8_t *copyPacket;
  while (currIf != NULL)
  {
    printf("$$$$ -> Send ARP request from interface %s.\n", currIf->name);

    memcpy(eth_hdr->ether_shost, (uint8_t *)currIf->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    sr_arp_hdr_t *apr_hdr = (sr_arp_hdr_t *)(arpPacket + sizeof(sr_ethernet_hdr_t));
    apr_hdr->ar_hrd = htons(1);
    apr_hdr->ar_pro = htons(2048);
    apr_hdr->ar_hln = 6;
    apr_hdr->ar_pln = 4;
    apr_hdr->ar_op = htons(arp_op_request);
    memcpy(apr_hdr->ar_sha, currIf->addr, ETHER_ADDR_LEN);
    memcpy(apr_hdr->ar_tha, (char *)generate_ethernet_addr(0), ETHER_ADDR_LEN);
    apr_hdr->ar_sip = currIf->ip;
    apr_hdr->ar_tip = ip;

    copyPacket = malloc(arpPacketLen);
    memcpy(copyPacket, eth_hdr, arpPacketLen);
    print_hdrs(copyPacket, arpPacketLen);
    sr_send_packet(sr, copyPacket, arpPacketLen, currIf->name);

    currIf = currIf->next;
  }
  printf("$$$ -> Send ARP request processing complete.\n");
}

/* Send an ICMP error. */
void sr_send_icmp_error_packet(uint8_t type,
                               uint8_t code,
                               struct sr_instance *sr,
                               uint32_t ipDst,
                               uint8_t *ipPacket)
{

  printf("### -> Send ICMP error.\n");
  /* packet initialization */
  unsigned int icmpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *packet = malloc(icmpPacketLen);

  /* packet headers */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp3Hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* initialize ethernet header */

  eth_hdr->ether_type = htons(ethertype_ip);
  memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
  memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
  

  icmp3Hdr->icmp_code = code;
  icmp3Hdr->icmp_type = type;

  ipHdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;;
  ipHdr->ip_v = 4;
  ipHdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ipHdr->ip_tos = 0;
  ipHdr->ip_id = htons(0);
  ipHdr->ip_off = htons(IP_DF);
  ipHdr->ip_ttl = 255;
  ipHdr->ip_p = ip_protocol_icmp;
  ipHdr->ip_dst = ipDst;
  
  memcpy(icmp3Hdr->data, ipPacket, ICMP_DATA_SIZE);

  icmp3Hdr->icmp_sum = icmp3_cksum(icmp3Hdr, sizeof(sr_icmp_t3_hdr_t)); /* calculate checksum */

  printf("### -> Check routing table, perform LPM.\n");
  struct sr_rt *longest_matching_entry = sr_get_lpm_entry(sr->routing_table, ipDst);
  if (longest_matching_entry)
  {
    printf("#### -> Match found in routing table. Check ARP cache.\n");

    struct sr_if *interface = sr_get_interface(sr, longest_matching_entry->interface);

    ipHdr->ip_src = interface->ip;
    ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));

    
    struct sr_arpentry *arpEntry = sr_arpcache_lookup(&(sr->cache), longest_matching_entry->gw.s_addr);
    if (arpEntry != NULL)
    {
      printf("##### -> Next-hop-IP to MAC mapping found in ARP cache. Forward packet to next hop.\n");
      memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, icmpPacketLen, interface->name);
    }
    else
    {
      printf("##### -> No next-hop-IP to MAC mapping found in ARP cache. Send ARP request to find it.\n");
      struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(sr->cache),
                                                      longest_matching_entry->gw.s_addr,
                                                      packet,
                                                      icmpPacketLen,
                                                      &(interface->name));
      handle_arpreq(sr, arpReq);
    }
  }
}


void sr_handle_arp_packet(struct sr_instance *sr,
                          uint8_t *packet /* lent */,
                          unsigned int len,
                          char *interface)
{

  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *apr_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, apr_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, apr_hdr->ar_tha, ETHER_ADDR_LEN);

  uint32_t senderIP = apr_hdr->ar_sip;
  uint32_t targetIP = apr_hdr->ar_tip;
  unsigned short op = ntohs(apr_hdr->ar_op);

  int update_flag = sr_arpcache_entry_update(&(sr->cache), senderIP);
  struct sr_arpentry *cached = sr_arpcache_lookup(&(sr->cache), senderIP);
  /* check if the ARP packet is for one of my interfaces. */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP);

  if (op == arp_op_request)
  {
    printf("**** -> It is an ARP request.\n");

    if (myInterface != 0)
    {
      printf("***** -> ARP request is for one of my interfaces.\n");

      printf("****** -> Construct an ARP reply and send it back.\n");

      memcpy(eth_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, senderHardAddr, ETHER_ADDR_LEN);

      memcpy(apr_hdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(apr_hdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      apr_hdr->ar_sip = targetIP;
      apr_hdr->ar_tip = senderIP;
      apr_hdr->ar_op = htons(arp_op_reply);
      sr_send_packet(sr, packet, len, myInterface->name);
    }
    printf("******* -> ARP request processing complete.\n");
  }
  else if (op == arp_op_reply)
  {
    printf("**** -> It is an ARP reply.\n");
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");

    struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
    if (!arpReq)
    {
      printf("****** -> Send outstanding packets.\n");

      struct sr_packet *unsent_packet = arpReq->packets;
      

      while (unsent_packet)
      {
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)unsent_packet->buf;
        memcpy(eth_hdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, senderHardAddr, ETHER_ADDR_LEN);

        sr_send_packet(sr, unsent_packet->buf, unsent_packet->len, myInterface);
        unsent_packet = unsent_packet->next;
      }
      sr_arpreq_destroy(&(sr->cache), arpReq);
    }
    printf("******* -> ARP reply processing complete.\n");
  }
}

void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet /* lent */,
                         unsigned int len,
                         char *interface )
{
  
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  printf("*** -> It is an IP packet. Print IP header.\n");

  struct sr_ip_hdr *ipHdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, ipHdr->ip_dst);
  struct sr_rt *longest_matching_entry = sr_get_lpm_entry(sr->routing_table, ipHdr->ip_dst);
  uint8_t ipProtocol = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

  if (!myInterface)
  {
    printf("*** -> Packet is not for one of my interfaces and no match found in routing table. Send ICMP net unreachable.\n");
    sr_send_icmp_error_packet(3, 0, sr, ipHdr->ip_src, ipHdr);
    return;
  }

  if (myInterface)
  {
    printf("***** -> IP packet is for one of my interfaces.\n");

    if (ipProtocol == ip_protocol_icmp)
    {
      printf("****** -> It is an ICMP packet. Print ICMP header.\n");


      sr_icmp_hdr_t *icmpHdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      if (icmpHdr->icmp_type == 8)
      {
        printf("******** -> It is an ICMP echo request. Send ICMP echo reply.\n");
        icmp_direct_echo_reply(sr, packet, len, interface, eth_hdr, ipHdr, icmpHdr);
        printf("********* -> ICMP echo request processing complete.\n");
      }
    }
    else
    {
      printf("****** -> IP packet is not an ICMP packet. Send ICMP port unreachable.\n");
      sr_send_icmp_error_packet(3, 3, sr, ipHdr->ip_src, (uint8_t *)ipHdr);
    }

    printf("********* -> IP packet processing complete.\n");
  }
  else
  {
    printf("***** -> IP packet is not for one of my interfaces.\n");

    ipHdr->ip_ttl--; /* decrement TTL count. */
    if (ipHdr->ip_ttl <= 0)
    {
      printf("****** -> TTL field is now 0. Send time exceeded.\n");
      sr_send_icmp_error_packet(11, 0, sr, ipHdr->ip_src, (uint8_t *)ipHdr);
    }
    else
    {
      ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t)); /* recompute checksum */
      struct sr_arpentry *arp_request = sr_arpcache_lookup(&sr->cache, longest_matching_entry->gw.s_addr);

      if (arp_request)
      {
        printf("******** -> Next-hop-IP to MAC mapping found in ARP cache. Forward packet to next hop.\n");

        struct sr_if *outInterface = sr_get_interface(sr, longest_matching_entry->interface);

        memcpy(eth_hdr->ether_dhost, arp_request->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, outInterface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, outInterface);
      }
      else
      {
        printf("******** -> No next-hop-IP to MAC mapping found in ARP cache. Send ARP request to find it.\n");

        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), longest_matching_entry->gw.s_addr, packet, len, &(longest_matching_entry->interface));
        handle_arpreq(sr, req);
      }
    }
  }
}