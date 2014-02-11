/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
 #include "trace_header.h"
 #include "udpClass.h"

udpManager::udpManager(uint16_t src_port) {
	
	// Creation of a packet with IP and source port defined
	packet = new udpClass(src_port);
}

address* udpManager::send(char* ip_address, uint16_t dest_port, int ttl, int payload) {
	int attempts[3];
	int udp_sock;
	char* c_payload;
	struct sockaddr_in dest;
	int probe;
	
	packet.setTtl(ttl);
	address* pun_list = new address;
	
	for(probe = 1; probe < N_PROBE_DEF; probe++) {
		if(ttl == 1){
			packet.setDest(ip_address, dest_port);
			attempts[probe] = dest_port++; // Keep track of the dest. ports used
		}
						
		// converts to decimal base
		sprintf(c_payload,"%d",payload);
		packet.setPayload(c_payload);
		
		pun_list->checksum[probe] = packet.getChecksum();
		udp_sock = packet.getSock();
		dest = packet.getDest();
		gettimeofday(&pun_list->time[probe], NULL);
		sendto(udp_sock, c_payload, sizeof(c_payload), 0, (struct sockaddr *)&dest, sizeof(dest));
		
		payload++;
	}
	
	return pun_list;
}		
