/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
 #include "udp.h"

udpManager::udpManager(uint16_t src_port) {
	udpPacket = new udpClass(src_port);
} 
	    
/* 
 * Sends 'n_probe' UDP packets to the destination specified in the parameteres
 * of the method. 
 * It fills 'vett_addr' with the information required 
*/
void udpManager::send(char* ip_address, uint16_t dest_port, int ttl, int payload, int n_probe, addr* vett_addr) {
    int udp_sock;
    
    //NOTE c_peyload becomes a void pointer to a memory location
    
    char c_payload[sizeof(int)];
    sockaddr_in* dest;
    int probe;
    
    udpPacket->setTtl(ttl);
    //set destination port and address
    udpPacket->setDest(ip_address, dest_port);
    
    for(probe = 0; probe < n_probe; probe++) {
        // converts payload from int to character
        //sprintf(c_payload, "%d", payload);
        memcpy(c_payload, &payload, sizeof(int));
        udpPacket->setPayload(c_payload);
        
        // calculates the checksum of the packet
        vett_addr[probe].checksum = udpPacket->getChecksum();

        udp_sock = udpPacket->getSock();
        dest = udpPacket->getDest();
        // setting the current time
        gettimeofday(&vett_addr[probe].time, NULL);
        // sends the UDP packet 
        int x = sendto(udp_sock, c_payload, sizeof(c_payload), 0, (sockaddr *)dest, 
                       sizeof(sockaddr));
        if(x != -1) cout<<"send ok\n";
        
        vett_addr[probe].ret = false;
        
        // changhes the payload for changing the checksum field [as Paris-traceroute does]
        payload++;
    }
}		
