/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
 #include "udpClass.h"

udpManager::udpManager(uint16_t src_port) : udpClass(src_port) {};
	
    // Creation of a packet with IP and source port defined

addr* udpManager::send(char* ip_address, uint16_t dest_port, int ttl, int payload, int n_probe) {
    int attempts[3];
    int udp_sock;
    char* c_payload;
    sockaddr_in dest;
    int probe;
    
    setTtl(ttl);
	addr* pun_list = null, *p = null;
    
    for(probe = 0; probe < n_probe; probe++) {
        
                      
        p = new addr;
        if(pun_list == null)
			pun_list = p;
						
        // converts to decimal base
        sprintf(c_payload,"%d",payload);
        setPayload(c_payload);
        
        p->checksum[probe] = getChecksum();
        udp_sock = getSock();
        dest = getDest();
        gettimeofday(&p->time[probe], NULL);
        sendto(udp_sock, c_payload, sizeof(c_payload), 0, 
            (sockaddr *)&dest, sizeof(dest));
        
        payload++;
        p->punt = null;
        p = p->punt;
    }
    
    return pun_list;
}		
