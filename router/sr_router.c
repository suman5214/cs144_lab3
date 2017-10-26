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

      if (len < sizeof(sr_arp_hdr_t) + ethernet_len) {
       printf("***** -> Invalid ARP packet length.\n");
      }
      print_hdr_arp(packet+ethernet_len);
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + ethernet_len);
      
      struct sr_if *dest = sr_get_interface_ip(sr, arp_hdr->ar_tip);
      if (!dest)
      { 
        Debug("ARP: not destined for router\n");
        return;
     }

      if (ntohs(arp_hdr->ar_op) == arp_op_request){
        printf("****ARP REQUEST!!!!!!\n");



        struct sr_if *intf = sr_get_interface(sr, interface);
        uint8_t *arpres = malloc(len);
        memcpy(arpres, packet, len);

            /* Update ethernet header */
        sr_ethernet_hdr_t *arpres_eth_hdr = (sr_ethernet_hdr_t *)arpres;
            /* Reply dest MAC address is request source MAC address */
        memcpy(arpres_eth_hdr->ether_dhost, arpres_eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(arpres_eth_hdr->ether_shost, intf->addr, ETHER_ADDR_LEN);

            /* Update ARP header */
        sr_arp_hdr_t *arpres_arp_hdr = (sr_arp_hdr_t *)(arpres + sizeof(sr_ethernet_hdr_t));
        arpres_arp_hdr->ar_op = htons(arp_op_reply);                     /* Reply operation */
        memcpy(arpres_arp_hdr->ar_sha, intf->addr, ETHER_ADDR_LEN);      /* Source MAC address */
        arpres_arp_hdr->ar_sip = intf->ip;                               /* Source IP address */
        memcpy(arpres_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN); /* Target MAC address */
        arpres_arp_hdr->ar_tip = arp_hdr->ar_sip;                        /* Target IP address */

        send_packet(sr, arpres, len, intf, arp_hdr->ar_sip);
        free(arpres);
      }

      else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
        printf("****ARP Reply!!!!!\n");
      }

    } else if (ethtype == ethertype_ip) {
      printf("**** -> Validate IP packet.\n");
      if (len < sizeof(sr_ip_hdr_t))
      {
        printf("***** -> Packet length is not correct.\n");
      }
    }


}/* end sr_ForwardPacket */

