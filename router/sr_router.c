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

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
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
struct sr_if *sr_get_interface_ip(struct sr_instance *sr, uint32_t ip)
{
    assert(ip);
    assert(sr);

    struct sr_if *intf = sr->if_list;
    while (intf)
    {
        if (intf->ip == ip)
        {
            return intf;
        }

        intf = intf->next;
    }

    return 0;
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  print_hdr_eth(packet);
  int ethernet_len = sizeof(sr_ethernet_hdr_t);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eth_hdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_arp) {

    sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eth_hdr);
  }
  else if(ethtype == ethertype_ip){
    printf("need to hand IPPPPPPPPP\n\n\n");
  }
}

void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,   
        sr_ethernet_hdr_t *eHdr) {

  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, arpHdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, arpHdr->ar_tha, ETHER_ADDR_LEN);

  uint32_t senderIP = arpHdr->ar_sip;
  uint32_t targetIP = arpHdr->ar_tip;
  unsigned short op = ntohs(arpHdr->ar_op);

  /* "refresh" the ARP cache entry associated with sender IP address
     if such an entry already exists. */
  int update_flag = sr_arpcache_lookup(&(sr->cache), senderIP); 

  /* check if the ARP packet is for one of my interfaces. */
  struct sr_if *myInterface = sr_get_interface_ip(sr, targetIP); 

  if (op == arp_op_request) {
    printf("**** -> It is an ARP request.\n");

    if (myInterface == 0) {
      printf("***** -> ARP request is not one of my interfaces.\n");
      return;
    }

      printf("****** -> Construct an ARP reply and send it back.\n");
      memcpy(eHdr->ether_shost, (uint8_t *) myInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN); 
      memcpy(eHdr->ether_dhost, (uint8_t *) senderHardAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);

      memcpy(arpHdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      arpHdr->ar_sip = targetIP;
      arpHdr->ar_tip = senderIP; 
      arpHdr->ar_op = htons(arp_op_reply);
      print_hdrs(packet, len);
      sr_send_packet(sr, packet, len, myInterface->name);

    printf("******* -> ARP request processing complete.\n");
  } else if (op == arp_op_reply) {
    printf("**** -> It is an ARP reply.\n");
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");

    if (update_flag == NULL) {
      struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
          if (arpReq) {
            printf("****** -> Send outstanding packets.\n");
                struct sr_packet *packet = arpReq->packets;

                struct sr_if *packet_intf = NULL;
                sr_ethernet_hdr_t *eth_hdr = NULL;

                while (packet)
                {
                    packet_intf = sr_get_interface(sr, packet->iface);

                    if (packet_intf)
                    {
                        /* Set src/dest MAC addresses */
                        eth_hdr = (sr_ethernet_hdr_t *)(packet->buf);
                        memcpy(eth_hdr->ether_dhost, arpHdr->ar_sha, ETHER_ADDR_LEN);
                        memcpy(eth_hdr->ether_shost, packet_intf->addr, ETHER_ADDR_LEN);

                        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                    }

                    packet = packet->next;
                }
                sr_arpreq_destroy(&sr->cache, arpReq);
            }
    }
    printf("******* -> ARP reply processing complete.\n");
  }
}

