#include "icmp.h"

/*s is referred to the source port
 * d to the FINAL destination port 
 */


//allocate a structure, this is the constructor in case the icmp has to be sent
icmpClass::icmpClass() {
}


//fills the fields of the class basing on the received message
/*
 * returns: 
 *       0 if ok
 *      -1 if error
*/
int icmpClass::icmpFill(char* message, int n){
    
    int iphdr_len, sent_iphdr_len, icmplen;
    
    //now in buffer I have the whole icmp packet that I needed
    dest_ip = (ip*) message;
    iphdr_len=dest_ip->ip_hl << 2;
    
    //check the fields of the icmp response
    if( ( icmplen = n - iphdr_len ) < ICMP_HDR_LENGTH )
        return -1;
    //copy icmp part of the message into icmp_msg
    icmp_msg = (icmp*)&message[iphdr_len];
    
    if(icmplen < ICMP_HDR_LENGTH + sizeof(ip)) 
        return -1;

    //construct the sent ip
    sent_ip = (ip*) (message + iphdr_len + ICMP_HDR_LENGTH);
    sent_iphdr_len = sent_ip->ip_hl << 2;
    if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) 
        return -1;
    
    //udp header
    udp = (udphdr*) (message + iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);

    return 0;
};
/*
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

        if(icmplen < ICMP_HDR_LENGTH + sizeof(ip)) 
            return -1;

        //construct the sent ip
        sent_ip = (ip*) (message + iphdr_len + ICMP_HDR_LENGTH);
        sent_iphdr_len = sent_ip->ip_len;
        if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) 
            return -1;
        
        //udp header
        udp = (udphdr*) (message + iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);

        return 0;

    }
    //if the message received isn't time exceeded check if the message is a 
    //port unreachable, so we reached the final destination
    else if(icmp_msg->icmp_type == ICMP_UNREACH) {

            if(icmplen < ICMP_HDR_LENGTH + sizeof(ip)) 
                return -1;

            //construct the sent ip
            sent_ip = (ip*) (message + iphdr_len + ICMP_HDR_LENGTH);
            sent_iphdr_len = sent_ip->ip_len;
            
            if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) 
                return -1;

            //udp header
            udp = (udphdr*) (message + iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);
        }
    return -1;
};*/

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

//converts from network mode to host mode
udphdr* icmpClass::getUDPHeader(){
  udphdr* tmp = udp;
  udp->dest = htons(tmp->dest);
  udp->source = htons(tmp->source);
  udp->check = udp->check;
  udp->len = htons(tmp->len);
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
uint16_t computeIcmpChecksum(const uint16_t* dgram, int length) {
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
    chs=computeIcmpChecksum((uint16_t*) icmp_msg, icmp_length);
    icmp_msg->icmp_cksum=chs;
};

uint16_t icmpClass::getChecksum(){
    return icmp_msg->icmp_cksum;
};


/*Redefine operator << in order to have simpler print functions*/
ostream& operator<<(ostream& out, icmpClass& ic) {
    
    //out<<"Final destination port: "<<ic.dest_port<<'\n';
    //out<<"Source port: "<<ic.source_port<<'\n';
    out<<"Type of the icmp: "<<ic.getICMPType()<<'\t';
    out<<"Code of the icmp: "<<ic.getICMPCode()<<'\n';
    
    return out;
    
}
