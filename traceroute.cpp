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
}

list<addr> traceroute::trace(char* ip_address, int max_ttl) {
    int payload = 1; //Initial payload has to be defined
    int ttl;
    uint16_t dest_port_ini = 32768 + 666; //NOTE possible optimization
    
    /* NOTE we need to assign that constant because we may receive less responses
     * of the number of probes sent hence we may need to change this number
     * in our case we decided to manage this number as follows:
     * if we send X probes (one for each port) 
     * and we recive N responses with N < X, for each port 
     * from which we received the answer we'll send in the next step X + (X%N) 
     * probes, hence the number of probes per port will be 
     * ceiling{[X + ceiling(X/N)] / X }   
     */
    int j, k;
    
    //vector of used dest port, useful for the icmp
    uint16_t dest_port[N_PROBE_DEF];
    addr address_vector[N_PROBE_DEF]; //to use when I send more probes
    addr address_ttl_1;         //address when ttl=1
    
    // udpManager to manage the udp packets are going to be sent
    udpManager uManager = new udpManager(src_port);
    
    for(ttl=1; ttl < max_ttl; ttl++) {
        // If ttl = 1, it sends 'N_PROBE_DEF' probes with different dest. ports
        if(ttl == 1) {
            for(int i = 0; i < N_PROBE_DEF; i++) {               
                dest_port[i] = dest_port_ini + i;
                // each packet has different payload and different dest. port
                uManager.send(ip_address, dest_port[i], ttl, payload++, 1, &address_ttl_1);
                ip_list[ttl].push_back(address_ttl_1);
            }
        }
        else {
			j = 0;
			k = 0;
			while(k < N_PROBE_DEF) {
				j = (j + 1) % N_PROBE_DEF;
				if(dest_port[j] != 0) {
					uManager.send(ip_address, dest_port[j], ttl, payload++, 1, address_vector);
					ip_list[ttl].push_back(address_vector[j]);
					k++;
				}
			}
        } 
	}
        
        //TODO ICMP receive and management 
        //NOTE remember to delete from the array the ports from which you don't receive 
        //answer   
    
    
            
    return *ip_list;
}
