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
	
	udpClass packet = new udpClass(ip_address, src_port);
	packet.setPayload(payload);
	
	for(ttl = 1; ttl <= max_ttl && done == 0; ttl++) {
		packet.setTtl(ttl);
		
		for(probe = 1; probe < n_probe; probe++) {
			if(ttl == 1){
				packet.setDestPort(dest_port);
				attempts[probe] = dest_port++; // Keep track of the dest. ports used
			}
			else if(probe == 1)
				packet.setDestPort(dest_port++);
							
			packet.setPayload(new_payload++);
			
		}
	}
		
	
}
