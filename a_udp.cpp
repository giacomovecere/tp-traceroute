#include "udp.h"

udp::udp(char* dest_addr, int dest_port,int source_port) {
    
    datagram.sockfd=Socket(AF_INET, SOCK_DGRAM, 0);   //socket file descriptor
    
    //destination structure initialization
    datagram.dest.sin_family=AF_INET;                
    datagram.dest.sin_port=htons(dest_port);        
    inet_pton(AF_INET, dest_addr, &datagram.dest.sin_addr);
    
    //source structure initialization
    datagram.src.sin_family=AF_INET;
    datagram.src.sin_port=htons(source_port);
    inet_pton(AF_INET, INADDR_ANY, &datagram.src.sin_addr);
    
    //bind the socket to the source address and port
    bind(datagram.sockfd, &datagram.src.sin_adrr, sizeof(sockaddr)); 
    	
}
