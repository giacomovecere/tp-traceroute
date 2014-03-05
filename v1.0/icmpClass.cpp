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

/* in te following code the 's' character is referred to the source port
 * the 'd' to the FINAL destination port 
 */


//allocate a structure, this is the constructor in case the icmp has to be sent
icmpClass::icmpClass() {
}

/* @Purpose: starting from the received message this function parses
 *           it in order to build correctly the various headers, the structure 
 *           of message can be seen in the header file
 * @Parameters: 
 *          (IN) message: all the message received with IP header
 *               n: size of the message
 * @Returns: 
 *       0 if ok
 *      -1 if error
 * 
 * NOTE: source is the host that receives the message, destination is
 * the host that sends the message, this role interchanging is due
 * to the fact that we decided to fix the role once for all, so be careful
 * and keep in mind this fact
 *  
*/
int icmpClass::icmpFillTrace(char* message, int n){
    
    int dest_iphdr_len, sent_iphdr_len, icmplen;
    
    dest_ip = (ip*) message;
    //ip_hl contains the number of 32-bit word in the ip header (min 5)
    //if we want to have the number of bytes we have to multiply it by 4
    dest_iphdr_len=dest_ip->ip_hl << 2; //ip_hl * 4
    
    //check the fields of the icmp response
    if( ( icmplen = n - dest_iphdr_len ) < (int)ICMP_HDR_LENGTH )
        return -1;
    //copy icmp part of the message into icmp_msg
    icmp_msg = (icmp*)(message + dest_iphdr_len);
    
    if(icmplen < (int)ICMP_HDR_LENGTH + (int)sizeof(ip)) 
        return -1;

    //construct the sent ip
    sent_ip = (ip*) (message + dest_iphdr_len + (int)ICMP_HDR_LENGTH);
    sent_iphdr_len = sent_ip->ip_hl << 2;
    if(icmplen < ICMP_HDR_LENGTH + sent_iphdr_len + 4) 
        return -1;
    
    //udp header
    udp = (udphdr*) (message + dest_iphdr_len + sent_iphdr_len + ICMP_HDR_LENGTH);

    return 0;
}

//same behavior of icmpFillTrace but used to parse an icmp echo reply
int icmpClass::icmpFillTP(char* message, int n){
    
    int dest_iphdr_len, icmp_len;
    
    dest_ip = (ip*) message;
    //ip_hl contains the number of 32-bit word in the ip header (min 5)
    //if we want to have the number of bytes we have to multiply it by 4
    dest_iphdr_len = dest_ip->ip_hl << 2;
    
    //int n1 = dest_ip->ip_len << 2;
    
    //check the fields of the icmp response
    icmp_len = n - dest_iphdr_len;
    if(icmp_len < ICMP_HDR_LENGTH)
        return -1;
    
    //copy icmp part of the message into icmp_msg
    icmp_msg = (icmp*)(message + dest_iphdr_len);

    return 0;
}

/* NOTE: 
 * once we receive something from the network we need to modify the bytes
 * ordering in order to be coherent with the one we're using on our host.
 * To do so we use a function named htons (host to network)
 * NOTE: 
 * since the checksum is computed on fields that are already in 
 * network ordering, we don't need to change the byte ordering of this field
 */

/* @Purpose: adapt the received udp in the host format*/
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

/* @Purpose: compute the icmp checksum
 * @Parameters: 
 *          (IN) dgram: fields needed to compute the checksum
 *               length: size of dgram
 * @Returns: checksum
 */
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

/* @Purpose: Make an icmp echo request to discover if an address (destAddr) is 
 *      classifiable or not for third part addresses discovery. It has to fill 
 *      buffer with an icmp echo request packet. Ip header is prepared by 
 *      ipManager that adds in the options field the timestamps options for 
 *      third part addresses discovery
 * @Parameters:
 *       (IN)
 *           msg: payload
 *           destAdd: destination address
 *       (OUT)
 *           len: length of the buffer
 * @Return: buffer that contains the whole icmp probe
*/
char* icmpClass::makeProbe(char* payload, char* destAddr, int& len){
    char* buffer;
    //init ip header
    ipManager* myIpManager = new ipManager(); //remember to deallocate it
    dest_ip = (ip*)myIpManager->prepareHeader(destAddr, 0);
    
    //bytes length of the ip header
    int dest_iphdr_len = dest_ip->ip_hl * 4;
    uint8_t dgram[ICMP_HDR_LENGTH + LENGTH_PAYLOAD];
    int chs = 0x0000;

    //init icmp header
    icmp_msg = new (icmp); //remember to deallocate it
    icmp_msg->icmp_code = 0;
    icmp_msg->icmp_type = ICMP_ECHO;
    icmp_msg->icmp_seq = 0;
    icmp_msg->icmp_id = getpid();
    icmp_length = ICMP_HDR_LENGTH;

    /* ICMP HEADER */ 
    memcpy(dgram, &icmp_msg->icmp_type, sizeof(icmp_msg->icmp_type));
    memcpy(dgram + 1, &icmp_msg->icmp_code, sizeof(icmp_msg->icmp_code));
    memcpy(dgram + 2, &chs, 2);
    memcpy(dgram + 4, &icmp_msg->icmp_id, sizeof(icmp_msg->icmp_id));
    memcpy(dgram + 6, &icmp_msg->icmp_seq, sizeof(icmp_msg->icmp_seq));
    
    /* PAYLOAD */
    memcpy(dgram + 8, payload, LENGTH_PAYLOAD);
    /* the ICMP cheksum is computed on the ICMP Header and the Payload */
    icmp_msg->icmp_cksum = computeIcmpChecksum((uint16_t*) dgram, 
                                             ICMP_HDR_LENGTH + LENGTH_PAYLOAD);
    
    //init the buffer and copy headers and payload into it
    len = dest_iphdr_len + icmp_length + LENGTH_PAYLOAD;
    buffer = new char[len]; //remember to deallocate it
    memcpy(buffer,dest_ip,dest_iphdr_len);
    memcpy(buffer+dest_iphdr_len,icmp_msg,icmp_length);
    memcpy(buffer+dest_iphdr_len+icmp_length,payload,LENGTH_PAYLOAD);
    
    //destroy the classes created
    delete icmp_msg;
    delete myIpManager;
    
    return buffer;
}
