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

        

        struct sr_arpentry *cached = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);

          if (cached)
          {
              /* Send out packet using cached ARP info */
              printf("send_packet: Using cached ARP\n");

              sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arpres;
              memcpy(eth_hdr->ether_shost, intf->addr, ETHER_ADDR_LEN); /* Source: MAC address from the interface that sent it */
              memcpy(eth_hdr->ether_dhost, cached->mac, ETHER_ADDR_LEN);     /* Dest: MAC address from ARP cache entry */

              sr_send_packet(sr, arpres, len, intf->name);
              
          }
          else
          {
              /* Queue ARP request */
              printf("send_packet: Queue ARP request\n");
              struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, arp_hdr->ar_sip, arpres, len, intf->name);
              handle_arpreq(sr, req);
          }

        free(cached);
        free(arpres);
      }

      else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
        printf("****ARP Reply!!!!!\n");
        struct sr_arpreq *cached = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            /* Send outstanding ARP packets */
            if (cached)
            {
                struct sr_packet *packet = cached->packets;

                struct sr_if *packet_intf = NULL;
                sr_ethernet_hdr_t *eth_hdr = NULL;

                while (packet)
                {
                    packet_intf = sr_get_interface(sr, packet->iface);

                    if (packet_intf)
                    {
                        /* Set src/dest MAC addresses */
                        eth_hdr = (sr_ethernet_hdr_t *)(packet->buf);
                        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                        memcpy(eth_hdr->ether_shost, packet_intf->addr, ETHER_ADDR_LEN);

                        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                    }

                    packet = packet->next;
                }

                sr_arpreq_destroy(&sr->cache, cached);
            }

      }

    } else if (ethtype == ethertype_ip) {
      printf("**** -> Validate IP packet.\n");
      if (len < sizeof(sr_ip_hdr_t))
      {
        printf("***** -> Packet length is not correct.\n");
      }
      handle_ip(sr, packet, len, interface);
        break;
    }


}/* end sr_ForwardPacket */

    void forward_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Decrement TTL */
    ip_hdr->ip_ttl--;

    /* Send "Time exceeded" ICMP message if the TTL causes the packet to be dropped */
    if (ip_hdr->ip_ttl == 0)
    {
        Debug("IP: TTL decremented to 0 (sending ICMP time exceeded)\n");
        send_icmp_msg(sr, packet, len, icmp_type_time_exceeded, (uint8_t)0);
        return;
    }

    /* Recompute IP header checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

    /* Look up in routing table with longest matching prefix */
    struct sr_rt *route = longest_matching_prefix(sr, ip_hdr->ip_dst);
    if (!route)
    {
        Debug("No route found (sending ICMP net unreachable)\n");
        send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_net);
        return;
    }

    struct sr_if *route_intf = sr_get_interface(sr, route->interface);
    if (!route_intf)
    {
        Debug("No interface found with name \"%s\"", route->interface);
        return;
    }

    send_packet(sr, packet, len, route_intf, route->gw.s_addr);
}

/* Custom: sends an ICMP message */
void send_icmp_msg(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code)
{
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Get longest matching prefix for source */
    struct sr_rt *route = longest_matching_prefix(sr, ip_hdr->ip_src);
    if (!route)
    {
        Debug("send_icmp_msg_addr: Routing table entry not found\n");
        return;
    }

    /* Get the sending interface */
    struct sr_if *sending_intf = sr_get_interface(sr, route->interface);

    switch (type)
    {
        /* Regular ICMP */
        case icmp_type_echo_reply:
        {
            /* Update Ethernet Header source host/destination host */
            memset(eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);

            /* Swap IP header source/destination */
            uint32_t old_ip_src = ip_hdr->ip_src;
            ip_hdr->ip_src = ip_hdr->ip_dst;
            ip_hdr->ip_dst = old_ip_src;

            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

            /* Create ICMP header */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;

            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

            send_packet(sr, packet, len, sending_intf, route->gw.s_addr);
            break;
        }

        /* Type 3 or Type 11 ICMP */
        case icmp_type_time_exceeded:
        case icmp_type_dest_unreachable:
        {
            /* Calculate new packet length */
            unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *new_packet = malloc(new_len);

            /* Sanity Check */
            assert(new_packet);

            /* Need to construct new headers for type 3 */
            sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)new_packet;
            sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));

            /* Init ethernet header */
            memset(new_eth_hdr->ether_shost, 0, ETHER_ADDR_LEN);
            memset(new_eth_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
            new_eth_hdr->ether_type = htons(ethertype_ip);

            /* Init IP header */
            new_ip_hdr->ip_v = 4;
            new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4; /* ip_hl is in words */
            new_ip_hdr->ip_tos = 0;
            new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            new_ip_hdr->ip_id = htons(0);
            new_ip_hdr->ip_off = htons(IP_DF);
            new_ip_hdr->ip_ttl = 255;
            new_ip_hdr->ip_p = ip_protocol_icmp;

            struct sr_rt *route = longest_matching_prefix(sr, ip_hdr->ip_src);
            if (!route)
            {
                Debug("send_icmp_msg: Routing table entry not found\n");
                return;
            }

            new_ip_hdr->ip_src = code == icmp_dest_unreachable_port ? ip_hdr->ip_dst : sending_intf->ip;
            new_ip_hdr->ip_dst = ip_hdr->ip_src;

            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

            /* Init ICMP header */
            new_icmp_hdr->icmp_type = type;
            new_icmp_hdr->icmp_code = code;
            new_icmp_hdr->unused = 0;
            new_icmp_hdr->next_mtu = 0; /* May need additional code here to handle code 4 */
            memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);

            new_icmp_hdr->icmp_sum = 0;
            new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

            send_packet(sr, new_packet, new_len, sending_intf, route->gw.s_addr);
            free(new_packet);
            break;
        }
    }
}

void handle_ip(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{
    Debug("IP: received packet\n");

    /* The actual contents of the packet */
    uint8_t *payload = (packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)payload;

    /* Drop packet if it's invalid */
    if (verify_ip(ip_hdr) == -1)
    {
        return;
    }

    /* Check if destined for one of the router's interfaces */
    struct sr_if *dest = sr_get_interface_ip(sr, ip_hdr->ip_dst);
    if (dest)
    {
        Debug("IP: destined for router\n");

        /* Destined for router: handle contained packet */
        switch (ip_hdr->ip_p)
        {
            /* ICMP messages */
            case ip_protocol_icmp:
            {
                Debug("IP: ICMP message\n");

                /* Verify ICMP header */
                if (verify_icmp(packet, len) == -1)
                {
                    return;
                }

                sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Handle "echo request" */
                if (icmp_hdr->icmp_type == icmp_type_echo_request)
                {
                    send_icmp_msg(sr, packet, len, icmp_type_echo_reply, (uint8_t)0);
                }

                break;
            }

            /* TCP/UDP: drop packet and send "destination unreachable" ICMP */
            case ip_protocol_tcp:
            case ip_protocol_udp:
            {
                Debug("IP: TCP/UDP message\n");
                send_icmp_msg(sr, packet, len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
                break;
            }
        }
    }
    else
    {
        /* Forward the packet to its actual destination */
        Debug("IP: destined elsewhere\n");

        forward_ip(sr, packet, len);
    }
}



