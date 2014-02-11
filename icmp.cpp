#include "icmp.h"

/*s is referred to the source port
 * d to the FINAL destination port 
 */
icmpClass::icmpClass(int s, int d) {
        
    sent_port=s; 
    dest_port=d;
    sockfd=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
};

//allocate a structure, this is the constructor in case the icmp has to be sent
icmpClass::icmpClass() {
    
    icmp_msg=new icmp;
    //set all the other fields to 0
    memset(icmp_msg, 0, sizeof(icmp));
    sockfd=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
}


//fills the fields of the class basing on the received message
/*returns 0 if intermediate router
 * 1 if port unreachable
 * -1 if error
 * the return value makes it easy to analyze the other fields
 */
int icmpClass::icmpFill(char* message, int n){
    
    int iphdr_len, sent_iphdr_len, icmplen;
    
    //now in buffer I have the whole icmp packet that I needed
    dest_ip = (ip*) message;
    iphdr_len=dest_ip->ip_len;
    
    //check the fields of the icmp response
    if( ( icmplen = n - iphdr_len ) < ICMP_HDR_LENGTH )
        return -1;
    
    //check if type and code are correct
    if(icmp_msg -> icmp_type == ICMP_TIME_EXCEEDED &&
        icmp_msg -> icmp_code == ICMP_TIMXCEED_INTRANS) {

        if(icmplen < ICMP_HDR_LENGTH + sizeof(ip)) return -1;

        //construct the sent ip
        sent_ip = (ip*) (message + iphdr_len + ICMP_HDR_LENGTH);
        sent_iphdr_len = sent_ip->ip_len;
        if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) return -1;
        
        //udp header
        udp = (udphdr*) (message + iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);

        if(sent_ip->ip_p == IPPROTO_UDP && 
            udp->uh_sport == htons(sent_port)
            && udp->uh_dport == htons(dest_port)) { //hence intermediate router
            
            return 0;
            
        }

    }
    
    /*
    * if the message received isn't time exceeded check if the message is a 
    * port unreachable, so we reached the final destination
    */
    else 
        if(icmp_msg->icmp_type == ICMP_UNREACH) {

            if(icmplen < ICMP_HDR_LENGTH + sizeof(ip)) return -1;

            //construct the sent ip
            sent_ip = (ip*) (message + iphdr_len + ICMP_HDR_LENGTH);
            sent_iphdr_len = sent_ip->ip_len;
            if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) return -1;

            //udp header
            udp = (udphdr*) (message + iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);

            if(sent_ip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sent_port)
                && udp->uh_dport == htons(dest_port)) { //hence final destination

                if(icmp_msg->icmp_code == ICMP_UNREACH_PORT)
                    return 1;
                else 
                    return -1;
            }
        }
    return -1;
};


int icmpClass::getSocket() {return sockfd;}

int icmpClass::getPort() {return dest_port;}

int icmpClass::getICMPCode() {
    return icmp_msg->icmp_code;
};

int icmpClass::getICMPType(){
    return icmp_msg->icmp_type;
};

//represents the structure of the ip header that includes the udp packet 
ip* icmpClass::getSourceIPHeader(){
    return sent_ip;
}

//ip header of the icmp packet
ip* icmpClass::getDestIPHeader(){ 
    return dest_ip;
}

udphdr* icmpClass::getUDPHeader(){
    return udp;
}

int icmpClass::getUDPChecksum() {
    return udp->check;
}

void icmpClass::setICMPCode(int c){
    
    if(icmp_msg==NULL) 
        icmp_msg=new(icmp);
    icmp_msg->icmp_code=c;
    
}

void icmpClass::setICMPType(int t){
    
    if(icmp_msg==NULL)
        icmp_msg=new(icmp);
    icmp_msg->icmp_type=t;
    
}

//set the icmp payload
void icmpClass::setICMPPayload(char* data, int len){
    
    //data has to be AT MOST 8 bytes
    memcpy(icmp_msg->icmp_data, data, len);
    icmp_length= ICMP_HDR_LENGTH + len;
    
}

/* Compute Internet Checksum by addind all the data contained in the 
 * datagram. In this case we need just the infos contained in the icmp*/
uint16_t computeChecksum(const uint16_t* dgram, int length) {
        uint32_t sum = 0;

        while (length > 1) {
                sum += *dgram++;
                length -= 2;
        }

        if (length > 0) sum += *(uint8_t*)dgram;

        // Put the sum on 16 bits by adding the two 16-bits parts
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

//set the icmp checksum field
void icmpClass::setChecksum(){
    
    int chs;
    chs=computeChecksum((uint16_t*) icmp_msg, icmp_length);
    icmp_msg->icmp_cksum=chs;
    
};


/*Redefine operator << in order to have simpler print functions*/
ostream& operator<<(ostream& out, icmpClass& ic) {
    
    //out<<"Final destination port: "<<ic.dest_port<<'\n';
    //out<<"Source port: "<<ic.source_port<<'\n';
    out<<"Type of the icmp: "<<ic.getICMPType()<<'\t';
    out<<"Code of the icmp: "<<ic.getICMPCode()<<'\n';
    
    return out;
    
}