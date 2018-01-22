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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"



#define DEFAULT_TTL           (255)




void Arp(struct sr_instance* sr,sr_arp_hdr_t *packet, unsigned int len,struct sr_if *iface);
void Ip(struct sr_instance* sr, uint8_t* packet, unsigned int length,char* interface);
int IpdestonUs(struct sr_instance* sr, sr_ip_hdr_t* Ipheader);
void ICMP_Echo_reply(struct sr_instance* sr, uint8_t* packet,unsigned int length,char* interface);
int ip_checksum(sr_ip_hdr_t *ip_header);
struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t next_hop);
struct sr_rt *find_routing_table(struct sr_instance *sr, uint32_t next_hop_ip);
void not_in_arp_sent(struct sr_instance* sr, struct sr_arpreq* request, struct sr_if* req_iface);
void ICMP_Port_unreachable(struct sr_instance* sr, uint8_t * packet,unsigned int length,char* interface);
void ICMP_Network_unreachable(struct sr_instance* sr, uint8_t * packet,unsigned int length,char* interface);
void ICMP_time_exceeded(struct sr_instance* sr, uint8_t * packet,unsigned int length,char* interface);
void ICMP_Host_unreachable(struct sr_instance* sr, uint8_t * packet,unsigned int length,char* interface);
void Setup_eth_and_sent(struct sr_instance *sr, sr_ethernet_hdr_t* packet, unsigned int length,struct sr_rt* route);


static const uint8_t broadcast[ETHER_ADDR_LEN] =
   { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

   /* fill in code here */

  /*check length whether enough*/
  if (len < sizeof(sr_ethernet_hdr_t))
  {
    /*The frame is too short, just drop it*/
     return;
  }

  printf("*** -> Received packet of length %d \n",len);

  struct sr_if* iface = sr_get_interface(sr, interface);
  if (!iface) {
      return;
  }

  /*ARP*/
  if (ethertype(packet) == ethertype_arp){
         
      sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
      int arp_length  = len- sizeof(sr_ethernet_hdr_t);
      Arp(sr,arp_hdr,arp_length,iface);
  }
         
  else if (ethertype(packet) == ethertype_ip){
      Ip(sr,packet,len,interface);
  }
  else{
    return;
  }
}/* end sr_ForwardPacket */

/*-------------------------------------------------------------------------------------------*/



/*--------------------------------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------*/
/*ARP*/
void Arp(struct sr_instance* sr,sr_arp_hdr_t* arp_hdr, unsigned int len, struct sr_if* iface){




   if (len < sizeof(sr_arp_hdr_t))
   {
      /* Not big enough to be an ARP packet... */
      return;
   }

   if (ntohs(arp_hdr->ar_op) == arp_op_request) {

        /*malloc space and built up reply packet*/

        uint8_t* reply_packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)reply_packet;
        sr_arp_hdr_t* arp_headr = (sr_arp_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t));



        /* ARP Header */
        arp_headr->ar_hln = ETHER_ADDR_LEN;
        arp_headr->ar_pln = 4;
        arp_headr->ar_hrd = htons(arp_hrd_ethernet);
        arp_headr->ar_pro = htons(ethertype_ip);
        arp_headr->ar_op = htons(arp_op_reply);
        arp_headr->ar_tip = arp_hdr->ar_sip;
        arp_headr->ar_sip = iface->ip;
        memcpy(arp_headr->ar_sha, iface->addr, ETHER_ADDR_LEN);
        memcpy(arp_headr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);




        /* Ethernet Header */
        memcpy(eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
        memcpy(eth_header->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

        eth_header->ether_type = htons(ethertype_arp);
            


        sr_send_packet(sr, reply_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
            iface->name);
            
        free(reply_packet);


    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {



        struct sr_arpreq* arqreq = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, ntohl(arp_hdr->ar_sip));
            
        if (arqreq != NULL)
        {      
            while (arqreq->packets != NULL)
            {
              struct sr_packet* temp = arqreq->packets;
              memcpy(((sr_ethernet_hdr_t*) temp->buf)->ether_dhost,
                  arp_hdr->ar_sha, ETHER_ADDR_LEN);
              sr_send_packet(sr, temp->buf, temp->len, temp->iface);
              arqreq->packets = arqreq->packets->next;

            }
        }
        else
        {
          return;
        }        

    }
}

/*--------------------------------------------------------------------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------------------------------------------*/
/*IP*/
void Ip(struct sr_instance* sr,uint8_t * packet,unsigned int len,char* interface){


    /*check Ip length*/
    if (len < sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t))
    {
       return;
    }

    sr_ip_hdr_t * ipheader = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /*checksum*/
    if (!ip_checksum(ipheader)) {
        return;
    }


    /*destination address on us*/
    if (IpdestonUs(sr, ipheader)==1)
    {

      if(ip_protocol((uint8_t*)ipheader) == ip_protocol_icmp){
        ICMP_Echo_reply(sr, packet, len,interface);

      }else{
        /*Port unreachable(3,3)*/
        ICMP_Port_unreachable(sr, packet, len,interface);
      }

    }else{
        struct sr_rf* in_routering_table = find_routing_table(sr, ipheader->ip_dst);

        if (!in_routering_table) {
          /*Network unreachable(3,0)*/
          ICMP_Network_unreachable(sr, packet, len,interface);
          return;
        }
        else if (ipheader->ip_ttl <= 1) {
          ICMP_time_exceeded(sr, packet, len,interface);
          return;
        }
        else{
          ipheader->ip_ttl = ipheader->ip_ttl-1;
          ipheader->ip_sum = 0;
          ipheader->ip_sum = cksum(ipheader, sizeof(sr_ip_hdr_t));
          Setup_eth_and_sent(sr,(sr_ethernet_hdr_t *) (packet),len, in_routering_table);
        }
        return;
    }
}


/*--------------------------------------------------------------------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------------------------------------------*/

void ICMP_Echo_reply(struct sr_instance* sr, uint8_t * packet,unsigned int length,char* interface)
{

  sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  int icmpLength = length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);



  struct sr_rt *route_table = find_routing_table(sr, ipheader->ip_src);

  if (!route_table) {
      return;
  }


  if(icmpHeader->icmp_type == (uint8_t)8){

    /*Send echo Reply*/
    uint8_t* replyPacket = (uint8_t *)malloc(length);

    memcpy(replyPacket, packet, length);


    sr_ip_hdr_t *replyIpHeader = (sr_ip_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *replyIcmpHeader = (sr_icmp_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

    /*setup ICMP*/
    replyIcmpHeader->icmp_type = (uint8_t)0;
    replyIcmpHeader->icmp_code = (uint8_t)0;
    replyIcmpHeader->icmp_sum = (uint16_t)0;
    replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, icmpLength);

    /* setup IP */
    uint32_t ip_src = replyIpHeader->ip_src;
    replyIpHeader->ip_src = replyIpHeader->ip_dst;
    replyIpHeader->ip_dst = ip_src;
    replyIpHeader->ip_ttl = INIT_TTL;
    replyIpHeader->ip_sum = 0;
    replyIpHeader->ip_sum = cksum(replyIpHeader, sizeof(sr_ip_hdr_t));

    Setup_eth_and_sent(sr, (sr_ethernet_hdr_t*) replyPacket,length, route_table);
  }else{
    return;
  }
}
/*--------------------------------------------------------------------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------------------------------------------*/


/*--------------------------------------------------------------------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------------------------------------------------------------------*/

int IpdestonUs(struct sr_instance* sr,sr_ip_hdr_t* Ipheader){
     struct sr_if* interface= sr->if_list;
     while (interface){
        if (Ipheader->ip_dst == interface->ip)
        {
           return 1;
        }else{
          interface = interface->next;
        }
     }
     
     return 0;
}


/*----------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------------------------------------------*/



int ip_checksum(sr_ip_hdr_t *ip_header) {
  uint16_t checksum_two, checksum_one = ip_header->ip_sum;
  int ip_length = ip_header->ip_hl * 4;;

  ip_header->ip_sum = 0;
  checksum_two = cksum(ip_header, ip_length);
  ip_header->ip_sum = checksum_one;
  if (checksum_one != checksum_two) {
    return 0;
  }
  return 1;
}

/*----------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------------------------------------------*/

struct sr_rt *find_routing_table(struct sr_instance *sr, uint32_t next_hop) {
  struct sr_rt *ans;
  struct sr_rt *current_table;
  uint32_t current_table_prefix, final_prefix, current_mask;

  ans = 0;
  
  for(current_table = sr->routing_table; current_table != NULL;current_table = current_table->next) {

    current_mask = current_table->mask.s_addr;
    current_table_prefix = current_table->dest.s_addr & current_mask;
    final_prefix = next_hop & current_mask;

    if (current_table_prefix == final_prefix){
      if(!ans || current_mask > ans->mask.s_addr){
        ans = current_table;
      }
    }
  }
  return ans;
}

/*----------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------------------------------------------*/


void Setup_eth_and_sent(struct sr_instance *sr, sr_ethernet_hdr_t* packet, unsigned int length,struct sr_rt* route)
{
   uint32_t next_hop;
   struct sr_arpentry* arp_entry;
         
   assert(route);
   /*get gw addr first*/
   next_hop = ntohl(route->gw.s_addr);
   /*look up cache*/
   arp_entry = sr_arpcache_lookup(&sr->cache, next_hop);
   
   packet->ether_type = htons(ethertype_ip);
   memcpy(packet->ether_shost, sr_get_interface(sr, route->interface)->addr, ETHER_ADDR_LEN);
   /*find it*/
   if (arp_entry != NULL)
   {
      memcpy(packet->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, (uint8_t*) packet, length, route->interface);
      
      free(arp_entry);
   }
   else
   {
      struct sr_arpreq* arpreq = sr_arpcache_queuereq(&sr->cache, next_hop,(uint8_t*) packet, length, route->interface);
      struct sr_if* req_iface = sr_get_interface(sr, route->interface);
      not_in_arp_sent(sr, arpreq,req_iface);
   }
}

/*----------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------------------------------------------*/

void not_in_arp_sent(struct sr_instance* sr, struct sr_arpreq* request, struct sr_if* req_iface)
{

   uint8_t* packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

   sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*) packet;

   sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

  
   /* ARP */
   arp_header->ar_sip = req_iface->ip;
   arp_header->ar_hln = ETHER_ADDR_LEN;
   arp_header->ar_pln = 4;
   arp_header->ar_hrd = htons(arp_hrd_ethernet);
   arp_header->ar_pro = htons(ethertype_ip);
   arp_header->ar_op = htons(arp_op_request);
   arp_header->ar_tip = htonl(request->ip);
   memcpy(arp_header->ar_sha, req_iface->addr, ETHER_ADDR_LEN);
   memset(arp_header->ar_tha, 0, ETHER_ADDR_LEN);


   /* Ethernet */
   memcpy(eth_header->ether_dhost, broadcast, ETHER_ADDR_LEN);
   memcpy(eth_header->ether_shost, req_iface->addr, ETHER_ADDR_LEN);
   eth_header->ether_type = htons(ethertype_arp);

   sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),req_iface->name);
   
}

/*----------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------------------------------------------*/

void ICMP_Port_unreachable(struct sr_instance* sr, uint8_t * packet,unsigned int length,char* interface){

  sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *route_table = find_routing_table(sr, ipheader->ip_src);

  if (!route_table) {
      return;
  }

  
  uint8_t* replyPacket = (uint8_t *)malloc(sizeof(sr_icmp_t3_hdr_t)  + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  sr_ip_hdr_t *replyIpHeader = (sr_ip_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *replyIcmpHeader = (sr_icmp_t3_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

  /*setup ICMP*/
  replyIcmpHeader->icmp_type = (uint8_t)3;
  replyIcmpHeader->icmp_code = (uint8_t)3;
  replyIcmpHeader->icmp_sum = (uint16_t)0;
  replyIcmpHeader->unused = 0;
  replyIcmpHeader->next_mtu = 0;
  memcpy(&replyIcmpHeader->data[0], ipheader, ICMP_DATA_SIZE);
  replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));

  /* setup IP */
  memcpy(replyIpHeader, ipheader, sizeof(sr_ip_hdr_t));
  replyIpHeader->ip_src = ipheader->ip_dst;
  replyIpHeader->ip_dst = ipheader->ip_src;
  replyIpHeader->ip_ttl = INIT_TTL;
  replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  replyIpHeader->ip_tos = 0;
  replyIpHeader->ip_p = ip_protocol_icmp;
  replyIpHeader->ip_sum = 0;
  replyIpHeader->ip_sum = cksum(replyIpHeader, sizeof(sr_ip_hdr_t));

  Setup_eth_and_sent(sr, (sr_ethernet_hdr_t*) replyPacket,sizeof(sr_icmp_t3_hdr_t)  + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), route_table);

}


/*----------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------------------------------------------*/


void ICMP_Network_unreachable(struct sr_instance* sr, uint8_t * packet,unsigned int length,char* interface){

  struct sr_if *iface = sr_get_interface(sr, interface);
  sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *route_table = find_routing_table(sr, ipheader->ip_src);

  if (!route_table) {
      return;
  }

  
  uint8_t* replyPacket = (uint8_t *)malloc(sizeof(sr_icmp_t3_hdr_t)  + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  sr_ip_hdr_t *replyIpHeader = (sr_ip_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *replyIcmpHeader = (sr_icmp_t3_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

  /*setup ICMP*/
  replyIcmpHeader->icmp_type = (uint8_t)3;
  replyIcmpHeader->icmp_code = (uint8_t)0;
  replyIcmpHeader->icmp_sum = (uint16_t)0;
  replyIcmpHeader->unused = 0;
  replyIcmpHeader->next_mtu = 0;
  memcpy(&replyIcmpHeader->data[0], ipheader, ICMP_DATA_SIZE);
  replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));

  /* setup IP */
  memcpy(replyIpHeader, ipheader, sizeof(sr_ip_hdr_t));
  replyIpHeader->ip_src = iface->ip;
  replyIpHeader->ip_dst = ipheader->ip_src;
  replyIpHeader->ip_ttl = DEFAULT_TTL;
  replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  replyIpHeader->ip_tos = 0;
  replyIpHeader->ip_p = ip_protocol_icmp;
  replyIpHeader->ip_sum = 0;
  replyIpHeader->ip_sum = cksum(replyIpHeader, sizeof(sr_ip_hdr_t));

  Setup_eth_and_sent(sr, (sr_ethernet_hdr_t*) replyPacket,sizeof(sr_icmp_t3_hdr_t)  + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), route_table);

}

/*----------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------------------------------------------*/

void ICMP_time_exceeded(struct sr_instance* sr, uint8_t * packet,unsigned int length,char* interface){

  struct sr_if *iface = sr_get_interface(sr, interface);
  sr_ip_hdr_t* ipheader = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *route_table = find_routing_table(sr, ipheader->ip_src);

  if (!route_table) {
      return;
  }

  
  uint8_t* replyPacket = (uint8_t *)malloc(sizeof(sr_icmp_t11_hdr_t)  + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  sr_ip_hdr_t *replyIpHeader = (sr_ip_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t *replyIcmpHeader = (sr_icmp_t11_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

  /*setup ICMP*/
  replyIcmpHeader->icmp_type = (uint8_t)11;
  replyIcmpHeader->icmp_code = (uint8_t)0;
  replyIcmpHeader->icmp_sum = (uint16_t)0;
  replyIcmpHeader->unused = 0;
  memcpy(&replyIcmpHeader->data[0], ipheader, ICMP_T11_DATA_SIZE);
  replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t11_hdr_t));

  /* setup IP */
  memcpy(replyIpHeader, ipheader, sizeof(sr_ip_hdr_t));
  replyIpHeader->ip_src = iface->ip;
  replyIpHeader->ip_dst = ipheader->ip_src;
  replyIpHeader->ip_ttl = DEFAULT_TTL;
  replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  replyIpHeader->ip_tos = 0;
  replyIpHeader->ip_p = ip_protocol_icmp;
  replyIpHeader->ip_sum = 0;
  replyIpHeader->ip_sum = cksum(replyIpHeader, sizeof(sr_ip_hdr_t));

  Setup_eth_and_sent(sr, (sr_ethernet_hdr_t*) replyPacket,sizeof(sr_icmp_t11_hdr_t)  + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), route_table);

}

/*----------------------------------------------------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------------------------------------------------*/
