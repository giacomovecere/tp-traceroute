/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "traceroute.h"

traceroute::traceroute(uint16_t s_port) {
	src_port = s_port;
	ip_list = 0;
}

address* traceroute::trace(char* ip_address, int max_ttl, int n_probe) {
	int ttl;
	int payload = 1; //Initial payload has to be defined
	uint16_t dest_port = 32768 + 666;
	int attempts[3];
	bool done = false;
	address* pun_list;
	int udp_sock;
	char* c_payload;
	struct sockaddr_in dest;
	
	// Creation of a packet with IP and source port defined
	udpClass packet = new udpClass(src_port);
	// The initial payload has been set
	packet.setPayload(payload);
	
	pun_list = ip_list;
	for(ttl = 1; ttl <= max_ttl && done == false; ttl++) {
		packet.setTtl(ttl);
		pun_list = new address;
		
		for(probe = 1; probe < n_probe; probe++) {
			if(ttl == 1){
				packet.setDest(ip_address, dest_port);
				attempts[probe] = dest_port++; // Keep track of the dest. ports used
			}
			//else if(probe == 1)
			//	packet.setDestPort(dest_port++);
							
			c_payload = (char)payload;
			packet.setPayload(c_payload);
			
			pun_list->checksum[probe] = packet.getChecksum()
			udp_sock = packet.getSock();
			dest = packet.getDest();
			gettimeofday(&pun_list->time[probe], NULL);
			sendto(udp_sock, c_payload, sizeof(c_payload), 0, (struct sockaddr *)&dest, sizeof(dest));
			
			
			payload++;
		}
	}
		
	
}
