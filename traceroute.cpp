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

address* traceroute::trace(char* ip_address, int max_ttl) {
	int payload = 1; //Initial payload has to be defined
	int ttl;
	uint16_t dest_port = 32768 + 666;
	bool done = false;
	address* ret_list;
	
	udpManager uManager = new udpManager(src_port);
	
	ret_list = ip_list;
	for(ttl = 1; ttl <= max_ttl && done == false; ttl++) {
		ret_list = uManager.send(ip_address, dest_port, ttl, payload);		
		/*if(ttl == 1){
            setDest(ip_address, dest_port);
            attempts[probe] = dest_port++; // Keep track of the dest. ports used
        }*/
		ret_list = ret_list->punt;
	}
		
	return ip_list;
}
