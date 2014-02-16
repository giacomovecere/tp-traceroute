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

int icmpManager::getSocket() { return sockfd; }

int icmpManager::getPort() { return s_port; }

/*
 * Return a struct addr* that contains 
 * response router informations and
 * sets host type
 *  0  intermediate router
 *  1  final destination
 * -1  error
*/
addr* icmpManager::recv(int* htype){
	
	char buffer[MESSAGE_SIZE];
    sockaddr_in rm_addr;
    socklen_t rm_addr_size;
    
    memset((char *)&rm_addr, 0, sizeof(rm_addr));
    //receive the response message
	int ret = recvfrom(sockfd,(void *)buffer,MESSAGE_SIZE,0,(sockaddr*)&rm_addr,&rm_addr_size);
	if(ret != -1){
		//ok
        icmpClass* icmpPkt = new icmpClass();
        //fill object with received message  
		int fill_ret = icmpPkt->icmpFill(buffer,MESSAGE_SIZE);

        addr* address = new addr;
        //set router ip address
		inet_ntop(AF_INET, &(rm_addr.sin_addr), address->ip, 20);
        //set current time
        gettimeofday (&(address->time), NULL);
        //compute and set the checksum
        icmpPkt->setChecksum();
		address->checksum = icmpPkt->getChecksum();
        //
        address->ret = false;

        //check if intermediate router reached 
        if(icmpPkt->getICMPType() == ICMP_TIME_EXCEEDED && icmpPkt->getICMPCode() == ICMP_TIMXCEED_INTRANS){ 
            *htype = 0;
        }
        //check if final destination reached 
        else if(icmpPkt->getICMPType() == ICMP_UNREACH){
            *htype = 1;
        } 
        else{
            //error
            *htype = -1;
        }

        return address;
	}
	else{
		//error
		return NULL;
	}
}
