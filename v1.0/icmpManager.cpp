/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "icmp.h"

icmpManager::icmpManager(uint16_t s){
    s_port = s;
    //socket that receives icmp packet
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd == -1) {
        cerr<<"error in building the socket\n";
        exit(EXIT_FAILURE);
    }
    //init struct for binding
    my_addr = new sockaddr_in;
    memset((char *)my_addr, 0, sizeof(*my_addr)); 
    my_addr->sin_family = AF_INET; 
    my_addr->sin_addr.s_addr = htonl(INADDR_ANY); 
    my_addr->sin_port = htons(s_port);
    
    bind(sockfd, (sockaddr*)my_addr, sizeof(*my_addr));
}

int icmpManager::getSocket() { return sockfd; }

//referred to the source
int icmpManager::getSourcePort() { return s_port; }

//referred to the destination
int icmpManager::getDestPort() {return d_port;}

/*
 * Return a struct addr* that contains 
 * response router informations and
 * sets host type:
 *    intermediate router
 *    final destination
 *    -1  error
*/
addr* icmpManager::traceRecv(int* htype){
	
	char buffer[MESSAGE_SIZE];
    sockaddr_in rm_addr;
    socklen_t rm_addr_size;
    
    memset((char *)&rm_addr, 0, sizeof(rm_addr));
    
    // to get the right ip address from the recvfrom function
    rm_addr_size = sizeof(struct sockaddr_in);
    //receive the response message
	int ret = recvfrom(sockfd,(void *)buffer,MESSAGE_SIZE,0,(sockaddr*)&rm_addr,&rm_addr_size);
	if(ret != -1) {
        icmpClass* icmpPkt = new icmpClass();
        //fill object with received message  
		int fill_ret = icmpPkt->icmpFill(buffer,MESSAGE_SIZE);
		
		//Change byte ordering according to our host and then retrieve port destination
        icmpPkt->adaptFromNetwork(icmpPkt->getUDPHeader());
		d_port = icmpPkt->getUDPHeader()->dest;

        addr* address = new addr;
        //set router ip address
		inet_ntop(AF_INET, &(rm_addr.sin_addr), address->ip, 20);
        //set current time
        gettimeofday (&(address->time), NULL);
		address->checksum = icmpPkt->getUDPChecksum();
        address->ret = false;

        //check if intermediate router reached 
        if(icmpPkt->getICMPType() == ICMP_TIME_EXCEEDED && icmpPkt->getICMPCode() == ICMP_TIMXCEED_INTRANS){ 
            *htype = INTERMEDIATE_ROUTER;
        }
        //check if final destination reached 
        else if(icmpPkt->getICMPType() == ICMP_UNREACH){
            *htype = FINAL_DESTINATION;
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

/*  
    send an icmp echo request
    parameters msg, srcAddr, destAddr, timestampAddr 
*/
void icmpManager::tpSend(char* msg, char* destAddr, char* timestamp){
    
    sockaddr_in dest;
    char* buffer;
    int len;
    
    icmpClass* icmpPkt = new icmpClass();    
    icmpPkt->makeProbe(destAddr,timestamp,dest,buffer,len);
    
    int ret = sendto(sockfd,buffer,len,0,(sockaddr *)&dest,sizeof(sockaddr));
}
