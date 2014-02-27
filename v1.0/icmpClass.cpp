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
#include "ip.h"

/* in te following code the 's' character is referred to the source port
 * the 'd' to the FINAL destination port 
 */


//allocate a structure, this is the constructor in case the icmp has to be sent
icmpClass::icmpClass() {
}


//fills the fields of the class basing on the received message
/*
 * returns: 
 *       0 if ok
 *      -1 if error
 * source is the host that receives the message, destination is
 * the host that sends the message, this role interchanging is due
 * to the fact that we decided to fix the role once for all, so be careful
 * and keep in mind this fact
 * 
 * @purpose: starting from the received message this function parses
 *                   it in order to build correctly the various headers, the structure 
 *                   of message can be seen in the header file 
*/
int icmpClass::icmpFill(char* message, int n){
    
    int dest_iphdr_len, sent_iphdr_len, icmplen;
    
    dest_ip = (ip*) message;
    dest_iphdr_len=dest_ip->ip_hl << 2;
    
    //check the fields of the icmp response
    if( ( icmplen = n - dest_iphdr_len ) < ICMP_HDR_LENGTH )
        return -1;
    //copy icmp part of the message into icmp_msg
    icmp_msg = (icmp*)(dest_ip + dest_iphdr_len);
    
    if(icmplen < ICMP_HDR_LENGTH + sizeof(ip)) 
        return -1;

    //construct the sent ip
    sent_ip = (ip*) (message + dest_iphdr_len + ICMP_HDR_LENGTH);
    sent_iphdr_len = sent_ip->ip_hl << 2;
    if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) 
        return -1;
    
    //udp header
    udp = (udphdr*) (message + dest_iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);

    return 0;
};

/* once we receive something from the network we need to modify the bytes
 * ordering in order to be coherent with the one we're using on our host.
 * To do so we use a function named htons (host to network)
 * 
 * NOTE: since the checksum is computed on fields that are already in 
 * network ordering, we don't need to change the byte ordering of this field
 */
void icmpClass::adaptFromNetwork(udphdr* u){
    u->source = htons(u->source);
    u->dest = htons(u->dest);
    u->len = htons(u->len);
}

/***********GET METHODS************/
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
    return udp;
}

int icmpClass::getUDPChecksum() {
    return udp->check;
}

uint16_t icmpClass::getChecksum(){
    return icmp_msg->icmp_cksum;
};

icmp* icmpClass::getICMPheader(){
    return icmp_msg;
}

/***********SET METHODS************/
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

/* Compute Internet Checksum by adding all the data contained in the 
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

/*Redefine operator << in order to have simpler print functions*/
ostream& operator<<(ostream& out, icmpClass& ic) {
    
    //out<<"Final destination port: "<<ic.dest_port<<'\n';
    //out<<"Source port: "<<ic.source_port<<'\n';
    out<<"Type of the icmp: "<<ic.getICMPType()<<'\t';
    out<<"Code of the icmp: "<<ic.getICMPCode()<<'\n';
    
    return out;
    
}

/*
    Make an icmp echo request to discover if an address (destAddr) is classifiable or not
    for third part addresses discovery
    This function receives the destination address, a timestamp, destination sockaddr_in, buffer and len
    It has to fill dest, buffer, len in order to make an icmp echo request packet
    Ip header is prepared by ipManager that adds in the options field the timestamps options for 
    third part addresses discovery
    At the end, buffer will contain the ip_header + icmp_header, len is the total packet len
*/
void icmpClass::makeProbe(char* destAddr, char* timestamp, sockaddr_in& dest, char* buffer, int& len){
    
    //init ip header
    ipManager* myIpManager = new ipManager(); //remember to deallocate it
    dest_ip = myIpManager->prepareHeader_ICMP(destAddr, timestamp);
    int dest_iphdr_len = dest_ip->ip_len << 2;
    
    //init icmp header
    icmp_msg = new (icmp); //remember to deallocate it
    icmp_msg->icmp_code = 0;
    icmp_msg->icmp_type = ICMP_ECHO;
    icmp_msg->icmp_seq = 0;
    icmp_msg->icmp_id = 0;
    icmp_length = ICMP_HDR_LENGTH;
    setChecksum();
    
    //destination structure initialization
    dest.sin_family = AF_INET;                
    dest.sin_port = htons(0);        
    inet_pton(AF_INET, destAddr, &dest.sin_addr);
    
    //init the buffer and copy headers into it
    buffer = new char[dest_iphdr_len + icmp_length]; //remember to deallocate it
    memcpy(buffer,dest_ip,dest_iphdr_len);
    memcpy(buffer+dest_iphdr_len,icmp_msg,icmp_length);    
   
    //delete myIpManager;
    
}