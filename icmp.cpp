#include "icmp.h"

icmpClass::icmpClass() {
	
	datagram.sockfd=Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	
}

char* icmpClass::getBuffer() {return datagram.buffer;}

int icmpClass::getSocket() {return datagram.sockfd;}
 
char* getSource() {
	return sock_ntop(&datagram.router_source, sizeof(sockaddr));
}

/*
 * returns: 
 * 1 in case is the last hop so we reached the destination
 * 0 in case is an intermediate router
 * -1 in case there's an error in the received ICMP packet
 * */
int icmpClass::recv(int* chs) {
	
	socklen_t len;
	ip* ip, *sent_ip;      //ip struct;
	int n;
	int iphdr_len, sent_iphdr_len, icmplen, ret;
	
	n=recvfrom(datagram.sockfd, (void*)datagram.buffer, 28, 0,
			&datagram.router_source, &len);
			
	if(n<0) { 
		cerr<<"n less than 0\n";
	    exit(-1);
    }
    
    //now in buffer I have the whole icmp packet that I needed
    ip= (ip*) datagram.buffer;
    iphdr_len=ip->h1 << 2;
    datagram.recmsg =  (icmp*) (datagram.buffer + iphdr_len);
    
    //check the fields of the icmp response
    if( ( icmplen = n-iphdr_len ) <8 )
        return false;
        
    if(datagram.recmsg -> icmp_type == ICMP_TIMXCEEDED &&
       datagram.recmsg -> icmp_code == ICMP_TIMXCEEDED_INTRANS) {
	   
	   if(icmplen < 8 + sizeof(ip)) return -1;
	   
	   //construct the sent ip
	   sent_ip = (ip*) (datagram.buffer + iphdr_len + 8);
	   sent_iphdr_len = sent_ip->h1 << 2;
	   if(icmplen < 8 + sent_iphdr_len + 4) return -1;
	   
	   udp = (udphdr*) (datagram.buffer + iphdr_len + sent_iphdr_len + 8);
	   
	   if()
	   
	   	   
    }
	       
    
};
