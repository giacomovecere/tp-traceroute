/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * 
 */

#include "icmp.h"

icmpManager::icmpManager(uint16_t s){
    s_port = s;
    //socket that receives icmp packet
    sockfd=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    //init struct for binding
    my_addr = new sockaddr_in;
    memset((char *)my_addr, 0, sizeof(*my_addr)); 
    my_addr->sin_family = AF_INET; 
    my_addr->sin_addr.s_addr = htonl(INADDR_ANY); 
    my_addr->sin_port = htons(s_port);
    
    bind(sockfd, (sockaddr*)my_addr, sizeof(*my_addr));
}

int icmpManager::getSocket() {return sockfd;}

addr* icmpManager::recv(){
	
	addr* address = new addr;
	char buffer[MESSAGE_SIZE];

    rm_addr = new sockaddr_in;
    memset((char *)rm_addr, 0, sizeof(*rm_addr));
	socklen_t rm_addr_size;
	int ret = recvfrom(sockfd,(void *)buffer,MESSAGE_SIZE,0,(sockaddr*)rm_addr,&rm_addr_size);
	if(ret != -1){
		//ok
        icmpClass* icmpPkt = new icmpClass();
		int fill_ret = icmpPkt->icmpFill(buffer,MESSAGE_SIZE);
		
		/*struct addr {
			char ip[20];
			struct timeval time[N_PROBE_DEF];
			uint16_t checksum[N_PROBE_DEF];
			addr* punt;
		};*/
        
		//addr* m_addr = new addr;
		//address->ip = 
		//address->checksum =
		//address->time =
	}
	else{
		//error
		return NULL;
	}
}