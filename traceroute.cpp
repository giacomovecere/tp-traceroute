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

#define N_PROBE 3

address* trace(char* ip_address, int src_port, int max_ttl = 30, char* payload) {
	int ttl;
	
	int dest_port = randomPort();
	
	udpClass packet = new udpClass(ip_address, dest_port, src_port);
	packet.setPayload(payload);
	old_payload = payload;
	
	for(ttl = 1; ttl <= max_ttl && done == 0; ttl++) {
		packet.setTtl(ttl);
		
		for(probe = 1; probe < N_PROBE; probe++) {
			new_payload = old_payload++;
			packet.setPayload(new_payload);
		}
	}
		
	
}
