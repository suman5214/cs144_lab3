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
void sr_arp_request_send(struct sr_instance *sr, uint32_t ip){
  printf("$$$ -> Send ARP request.\n");

  uint8_t *mac_addr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  mac_addr[0] = 255;
  mac_addr[1] = 255;
  mac_addr[2] = 255;
  mac_addr[3] = 255;
  mac_addr[4] = 255;
  mac_addr[5] = 255;
  int arpPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *arpPacket = malloc(arpPacketLen);

  sr_ethernet_hdr_t *eth_hdr = (struct sr_ethernet_hdr *)arpPacket;
  memcpy(eth_hdr->ether_dhost, mac_addr, ETHER_ADDR_LEN);

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
    memcpy(apr_hdr->ar_tha, (char *)mac_addr, ETHER_ADDR_LEN);
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

 struct sr_if* get_IP(struct sr_instance* sr, uint32_t ip)
{
    /* -- REQUIRES -- */
    assert(ip);
    assert(sr);

    struct sr_if* iFace = sr->if_list;

    while(iFace)
    {
       if(iFace->ip != ip)
        { 
          iFace = iFace->next; 
        }
      else{
        return iFace; 
      }
    }
    return 0;
}
uint32_t ip_cksum (sr_ip_hdr_t *ipHdr, int len) {
  uint16_t currChksum, calcChksum;

  currChksum = ipHdr->ip_sum; 
  ipHdr->ip_sum = 0;
  calcChksum = cksum(ipHdr, len);
  ipHdr->ip_sum = currChksum;    

  return calcChksum;
}

uint32_t icmp_cksum (sr_icmp_hdr_t *icmpHdr, int len) {
  uint16_t currChksum, calcChksum;

  currChksum = icmpHdr->icmp_sum; 
  icmpHdr->icmp_sum = 0;
  calcChksum = cksum(icmpHdr, len);
  icmpHdr->icmp_sum = currChksum;

  return calcChksum;
}


void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet,
                     unsigned int len,
                     char *interface )
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  print_hdr_eth(packet);

    if (ethertype(packet) == ethertype_arp)
    {
      printf("This is a ARP packet \n");
      handle_ARP(sr, packet, len, interface);
    }
    else if (ethertype(packet) == ethertype_ip)
    {
      printf("This is a IP packet \n");
      handle_IP(sr, packet, len, interface);
    }
}  

void send_icmp_packet(struct sr_instance *sr,
                               uint32_t sender_add,
                               uint8_t *icmp_packet,
                               uint8_t type,
                               uint8_t code,
                               unsigned int len,
                               char *interface )
{
  if(type ==0 && code == 0){
    
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
        struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
        struct sr_if *Iface = sr_get_interface(sr, interface);
        uint8_t *tempAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(tempAddr, eth_hdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);

        /*Set icmp header*/
        icmp_hdr->icmp_type = 0;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
        /*Set ip header*/
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = Iface->ip;
        ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN); 
        memcpy(eth_hdr->ether_shost, tempAddr, ETHER_ADDR_LEN);
        
        sr_send_packet(sr, icmp_packet, len, interface);
  }
  else{
    uint8_t *packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    
    /* initialize ethernet header */

    eth_hdr->ether_type = htons(ethertype_ip);
    memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
    memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);

    /* initialize icmp header */
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_type = type;
    memcpy(icmp_hdr->data, icmp_packet, ICMP_DATA_SIZE);

    /* initialize ip header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_dst = sender_add;
    ip_hdr->ip_id = htons(0);
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = ip_protocol_icmp;
    
    uint16_t currChksum, calcChksum;
    currChksum = icmp_hdr->icmp_sum; 
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    struct sr_rt *longest_matching_entry = sr_get_lpm_entry(sr->routing_table, sender_add);
    if (!longest_matching_entry)
    {
      printf("No MAC->IP record in talbe\n");
      return;
    }
      struct in_addr *lmp_addr = longest_matching_entry->gw.s_addr;
      struct sr_if *iFace = sr_get_interface(sr, longest_matching_entry->interface);
      struct sr_arpentry *arp_req = sr_arpcache_lookup(&(sr->cache), lmp_addr);
      
      if (arp_req)
      {
        ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        ip_hdr->ip_src = iFace->ip;
        memcpy(eth_hdr->ether_dhost, arp_req->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, iFace->addr, ETHER_ADDR_LEN); 
        sr_send_packet(sr, packet, sizeof(packet), iFace->name);
      }
      else
      {
        ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        ip_hdr->ip_src = iFace->ip;
        struct sr_arpreq *arpReq = sr_arpcache_queuereq(&(sr->cache),lmp_addr,packet,sizeof(packet),iFace->name);
        handle_arpreq(sr, arpReq);
      }
    }
}


void handle_ARP(struct sr_instance *sr,
                          uint8_t *packet ,
                          unsigned int len,
                          char *iFace)
{
  sr_arp_hdr_t *apr_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  struct sr_if *curIFACE = get_IP(sr, apr_hdr->ar_tip);

  if (ntohs(apr_hdr->ar_op) == arp_op_request)
  {
    printf("This is a ARP request.\n");

    if (curIFACE != 0)
    {
      /* Construct ARP packet*/
      memcpy(eth_hdr->ether_shost, curIFACE->addr, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, apr_hdr->ar_sha, ETHER_ADDR_LEN);

      unsigned char temp[ETHER_ADDR_LEN];
      memcpy(temp, apr_hdr->ar_sha, ETHER_ADDR_LEN);
      
      /*UPdate APR package MAC*/
      memcpy(apr_hdr->ar_sha, curIFACE->addr, ETHER_ADDR_LEN);
      memcpy(apr_hdr->ar_tha, temp, ETHER_ADDR_LEN);

      /*UPdate APR package IP*/
      apr_hdr->ar_sip = apr_hdr->ar_tip;
      apr_hdr->ar_tip = apr_hdr->ar_sip;
      apr_hdr->ar_op = htons(arp_op_reply);
      sr_send_packet(sr, packet, len, curIFACE->name);
    }
  }
  else if (ntohs(apr_hdr->ar_op) == arp_op_reply)
  {
    printf("It is an ARP reply.\n");

    struct sr_arpreq *arp_req = sr_arpcache_insert(&(sr->cache), apr_hdr->ar_sha, apr_hdr->ar_sip);
    if (!arp_req)
    {
      printf("Send outstanding packets.\n");

      struct sr_packet *unsent_packet = arp_req->packets;
      

      while (unsent_packet)
      {
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)unsent_packet->buf;
        memcpy(eth_hdr->ether_shost, curIFACE->addr, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, apr_hdr->ar_sha, ETHER_ADDR_LEN);

        sr_send_packet(sr, unsent_packet->buf, unsent_packet->len, curIFACE);
        unsent_packet = unsent_packet->next;
      }
      sr_arpreq_destroy(&(sr->cache), arp_req);
    }
  }
  else{
    printf("Not valid ARP OP CODE\n");
  }
}

void handle_IP(struct sr_instance *sr,
                         uint8_t *packet /* lent */,
                         unsigned int len,
                         char *interface )
{
  
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;


  struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *curIFACE = get_IP(sr, ip_hdr->ip_dst);
  struct sr_rt *longest_matching_entry = sr_get_lpm_entry(sr->routing_table, ip_hdr->ip_dst);
  uint8_t ipProtocol = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

  if (curIFACE)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    if (icmp_hdr->icmp_type == 8)
    {
      send_icmp_packet(sr, ip_hdr->ip_src, packet,0, 0,len,interface);
    }
    else
    {
      send_icmp_packet(sr, ip_hdr->ip_src, ip_hdr,3, 3,len,interface);
    }
  }
  else
  {

    ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1 ; 
    if (ip_hdr->ip_ttl > 0)
    {
      ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      struct sr_arpentry *arp_request = sr_arpcache_lookup(&sr->cache, longest_matching_entry->gw.s_addr);

      if (arp_request)
      {
        struct sr_if *nextIFACE = sr_get_interface(sr, longest_matching_entry->interface);

        memcpy(eth_hdr->ether_dhost, arp_request->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, nextIFACE->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, nextIFACE);
      }
      else
      {
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), longest_matching_entry->gw.s_addr, packet, len, &(longest_matching_entry->interface));
        handle_arpreq(sr, req);
      }
      
    }
    else
    {
      send_icmp_packet( sr, ip_hdr->ip_src, ip_hdr,11, 0,len,interface);
    }
  }
}