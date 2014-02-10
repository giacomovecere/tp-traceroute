#include "icmp.h"

/*function taken from Unix Network Programming 
 * by Stevens, Fenner, Rudoff
 * converts an Internet address into a char
 * this function has been modified in order to 
 * deal only with IPv4
 */ 

char* sock_ntop(sockaddr* sa, socklen_t salen) {
    
    char portstr[8];
    static char str[128];
    
    sockaddr_in *sin = (sockaddr_in* )sa;
    if(inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
	return NULL;
    if(ntohs(sin->sin_port) != 0) {
	
	strcat(str, portstr);
	
    }
    
    return str;
    
}

icmpClass::icmpClass(int s, int d) {
	
    sent_port=s; 
    dest_port=d;
    datagram.sockfd=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	
}

char* icmpClass::getBuffer() {return datagram.buffer;}

int icmpClass::getSocket() {return datagram.sockfd;}

char* icmpClass::getIP() {return ipAddress;}

int icmpClass::getPort() {return dest_port;}
 
/*char* icmpClass::getSource() {
    return sock_ntop(&datagram.router_source, sizeof(sockaddr));
}*/

/* receive an ICMP packet and check all the infos about it
 * returns: 
 * 1 in case is the last hop so we reached the destination
 * 0 in case is an intermediate router
 * -1 in case there's an error in the received ICMP packet
 * */
int icmpClass::recv(int* chs) {
	
    socklen_t len;
    ip* dest_ip, *sent_ip;      //ip struct
    udphdr* udp;                //udp header
    int n;
    int iphdr_len, sent_iphdr_len, icmplen, ret;

    //receive the icmp packet
    n=recvfrom(datagram.sockfd, (void*)datagram.buffer, 28, 0,
    &datagram.router_source, &len);

    if(n<0) { 
	cerr<<"n less than 0\n";
	exit(-1);
    }

    //now in buffer I have the whole icmp packet that I needed
    dest_ip = (ip*) datagram.buffer;
    iphdr_len=dest_ip->ip_len;
    datagram.rec_msg =  (icmp*) (datagram.buffer + iphdr_len);

    //check the fields of the icmp response
    if( ( icmplen = n - iphdr_len ) <8 )
	return false;

    if(datagram.rec_msg -> icmp_type == ICMP_TIME_EXCEEDED &&
	datagram.rec_msg -> icmp_code == ICMP_TIMXCEED_INTRANS) {

	if(icmplen < 8 + sizeof(ip)) return -1;

	//construct the sent ip
	sent_ip = (ip*) (datagram.buffer + iphdr_len + 8);
	sent_iphdr_len = sent_ip->ip_len;
	if(icmplen < 8 + sent_iphdr_len + 4) return -1;

	//udp header
	udp = (udphdr*) (datagram.buffer + iphdr_len + sent_iphdr_len + 8);

	if(sent_ip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sent_port)
	    && udp->uh_dport == htons(dest_port)) { //hence intermediate router

	//extract the IP string
	    ipAddress = sock_ntop(&datagram.router_source, len);

	    //now put the checksum to let the main program do the checking 
	    *chs=udp->check;

	    return 0;
	}

	else return -1;

    }

    /*
    * if the message received isn't time exceeded check if the message is a 
    * port unreachable, so we reached the final destination
    */
    else if(datagram.rec_msg->icmp_type == ICMP_UNREACH) {

	if(icmplen < 8 + sizeof(ip)) return -1;

	//construct the sent ip
	sent_ip = (ip*) (datagram.buffer + iphdr_len + 8);
	sent_iphdr_len = sent_ip->ip_len;
	if(icmplen < 8 + sent_iphdr_len + 4) return -1;

	//udp header
	udp = (udphdr*) (datagram.buffer + iphdr_len + sent_iphdr_len + 8);

	if(sent_ip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sent_port)
	    && udp->uh_dport == htons(dest_port)) { //hence intermediate router

	    //extract the IP string
	    ipAddress = sock_ntop(&datagram.router_source, len);

	    //now put the checksum to let the main program do the checking 
	    *chs=udp->check;

	    if(datagram.rec_msg->icmp_code == ICMP_UNREACH_PORT)
		return 1;
	    else 
		return -1;
	}
    }
    return -1;

};
