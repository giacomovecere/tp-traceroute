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

int icmpManager::getPort() {return s_port;}

addr* icmpManager::recv(int* htype){
	
	char buffer[MESSAGE_SIZE];
    sockaddr_in rm_addr;
    socklen_t rm_addr_size;
    
    memset((char *)&rm_addr, 0, sizeof(rm_addr));
	int ret = recvfrom(sockfd,(void *)buffer,MESSAGE_SIZE,0,(sockaddr*)&rm_addr,&rm_addr_size);
	if(ret != -1){
		//ok
        icmpClass* icmpPkt = new icmpClass();
		int fill_ret = icmpPkt->icmpFill(buffer,MESSAGE_SIZE);
        
        addr* address = new addr;
		inet_ntop(AF_INET, &(rm_addr.sin_addr), address->ip, 20);
        gettimeofday (&(address->time), NULL);
        icmpPkt->setChecksum();
		address->checksum = icmpPkt->getChecksum();
	    address->ret = false;

        if(icmpPkt->getICMPType() == ICMP_TIME_EXCEEDED && icmpPkt->getICMPCode() == ICMP_TIMXCEED_INTRANS){
            //hence intermediate router  
            *htype = 0;
        } 
        else if(icmpPkt->getICMPType() == ICMP_UNREACH){
            //hence final destination
            *htype = 1;
        } 
        else{ 
            *htype = -1;
        }

        /*
        if(sent_ip->ip_p == IPPROTO_UDP 
            && udp->uh_sport == htons(sent_port)
            && udp->uh_dport == htons(dest_port)) { 
            //hence intermediate router
            *htype = 0;
            
        }
        if(sent_ip->ip_p == IPPROTO_UDP 
            && udp->uh_sport == htons(sent_port)
            && udp->uh_dport == htons(dest_port)) { 
            //hence final destination
            if(icmp_msg->icmp_code == ICMP_UNREACH_PORT)
                *htype = 1;
            else 
                *htype = -1;
        }
        */

        return address;
	}
	else{
		//error
		return NULL;
	}
}