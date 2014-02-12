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
	    
/* 
 * Sends 'n_probe' UDP packets to the destination specified in the parameteres
 * of the method. 
 * It returns an 'addr' list with a length corresponding to the last parameter 
*/
addr* udpManager::send(char* ip_address, uint16_t dest_port, int ttl, int payload, int n_probe) {
    int udp_sock;
    char* c_payload;
    sockaddr_in dest;
    int probe;
    
    setTtl(ttl);
	addr* pun_list = NULL, *p = NULL;
    
    for(probe = 0; probe < n_probe; probe++) {
        p = new addr;
        if(pun_list == NULL)
			pun_list = p;
						
        // converts to decimal base
        sprintf(c_payload, "%d", payload);
        setPayload(c_payload);
        
        p->checksum = getChecksum();
        udp_sock = getSock();
        dest = getDest();
        // setting the current time
        gettimeofday(&p->time, NULL);
        // sends the UDP packet 
        sendto(udp_sock, c_payload, sizeof(c_payload), 0, (sockaddr *)&dest, sizeof(dest));
        
        p->ret = false;
        
        // changhes the payload for changing the checksum field [as Paris-traceroute does]
        payload++;
        
        p->punt = NULL;
        p = p->punt;
    }
    
    return pun_list;
}		
