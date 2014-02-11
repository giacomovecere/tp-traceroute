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

/*s is referred to the source port
 * d to the FINAL destination port 
 */
icmpClass::icmpClass(int s, int d) {
        
    sent_port=s; 
    dest_port=d;
    datagram.sockfd=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
}

int icmpClass::getSocket() {return datagram.sockfd;}

//it's the IP of the entity that sends the ICMP packet
char* icmpClass::getIP() {return ipAddress;}

int icmpClass::getPort() {return dest_port;}

int icmpClass::getICMPCode() {
    return datagram.rec_msg->icmp_code;
};

int icmpClass::getICMPType(){
    return datagram.rec_msg->icmp_type;
};

//represents the structure of the ip header that includes the udp packet 
ip* icmpClass::getSourceIPHeader(){
    return datagram.sent_ip;
}

//ip header of the icmp packet
ip* icmpClass::getDestIPHeader(){ 
    return datagram.dest_ip;
}


udphdr* icmpClass::getUDPHeader(){
    return datagram.udp;
}



/*char* icmpClass::getSource() {
    return sock_ntop(&datagram.router_source, sizeof(sockaddr));
}*/

/* receive an ICMP packet and check all the infos about it
 * returns: 
 * 1 in case is the last hop so we reached the destination
 * 0 in case is an intermediate router
 * -1 in case there's an error in the received ICMP packet
 * The parameter passed by reference represents the checksum of
 * the received UDP
 * */
int icmpClass::recv(int* chs) {
    
    char message[MESSAGE_SIZE]; //buffer in which we put the received message 
    socklen_t len;
    int n;
    int iphdr_len, sent_iphdr_len, icmplen;

    //receive the icmp packet
    n=recvfrom(datagram.sockfd, message, MESSAGE_SIZE, 0,
    &datagram.router_source, &len);

    if(n<0) { 
        cerr<<"n less than 0\n";
        exit(-1);
    }

    //now in buffer I have the whole icmp packet that I needed
    datagram.dest_ip = (ip*) message;
    iphdr_len=datagram.dest_ip->ip_len;
    //datagram.rec_msg =  (icmp*) (message + iphdr_len);

    //check the fields of the icmp response
    if( ( icmplen = n - iphdr_len ) < ICMP_HDR_LENGTH )
        return -1;

    if(datagram.rec_msg -> icmp_type == ICMP_TIME_EXCEEDED &&
        datagram.rec_msg -> icmp_code == ICMP_TIMXCEED_INTRANS) {

        if(icmplen < ICMP_HDR_LENGTH + sizeof(ip)) return -1;

        //construct the sent ip
        datagram.sent_ip = (ip*) (message + iphdr_len + ICMP_HDR_LENGTH);
        sent_iphdr_len = datagram.sent_ip->ip_len;
        if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) return -1;

        //udp header
        datagram.udp = (udphdr*) (message + iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);

        if(datagram.sent_ip->ip_p == IPPROTO_UDP && 
            datagram.udp->uh_sport == htons(sent_port)
            && datagram.udp->uh_dport == htons(dest_port)) { //hence intermediate router

            //extract the IP string
            //NOTE inet_ntop may be sufficient for our purposes
            ipAddress = sock_ntop(&datagram.router_source, len);

            //now put the checksum to let the main program do the checking 
            *chs=datagram.udp->check;

            return 0;
        }

        else return -1;

    }

    /*
    * if the message received isn't time exceeded check if the message is a 
    * port unreachable, so we reached the final destination
    */
    else if(datagram.rec_msg->icmp_type == ICMP_UNREACH) {

        if(icmplen < ICMP_HDR_LENGTH + sizeof(ip)) return -1;

        //construct the sent ip
        datagram.sent_ip = (ip*) (message + iphdr_len + ICMP_HDR_LENGTH);
        sent_iphdr_len = datagram.sent_ip->ip_len;
        if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) return -1;

        //udp header
        datagram.udp = (udphdr*) (message + iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);

        if(datagram.sent_ip->ip_p == IPPROTO_UDP && 
            datagram.udp->uh_sport == htons(sent_port)
            && datagram.udp->uh_dport == htons(dest_port)) { //hence final destination

            //extract the IP string
            ipAddress = sock_ntop(&datagram.router_source, len);

            //now put the checksum to let the main program do the checking 
            *chs=datagram.udp->check;

            if(datagram.rec_msg->icmp_code == ICMP_UNREACH_PORT)
                return 1;
            else 
                return -1;
        }
    }
    return -1;

};

/*Redefine operator << in order to have simpler print functions*/
ostream& operator<<(ostream& out, icmpClass& ic) {
    
    //out<<"Final destination port: "<<ic.dest_port<<'\n';
    //out<<"Source port: "<<ic.source_port<<'\n';
    out<<"IP of the sender of the ICMP: "<<ic.getIP()<<'\n';
    out<<"Type of the icmp: "<<ic.getICMPType()<<'\t';
    out<<"Code of the icmp: "<<ic.getICMPCode()<<'\n';
    
    return out;
    
}