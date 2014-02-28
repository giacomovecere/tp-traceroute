#include "ip.h"

//this is the constructor of the ip class, we initialize all the constants fields
/* NOTE: as stated in the RAW(7) some of the fields are filled by the kernel hence 
 * there may be the interface of the calling to the function, but it will not 
 * be implemented since the hardware provides the answer to this question
 */
ipClass::ipClass(){
    
    ipHeader = new ip;
    
    
    //BEGIN initialization of the IP header
    /* the length of the header needs to be computed:
     * 5 is the standard length
     * timestamp option takes 9 * 4 bytes
     * hence ip header length is 14 bytes
    */
    //ipHeader->ip_hl = IP_TS_LENGTH;
    //we use only IPv4
    ipHeader->ip_v = IPv4;
    /* NOTE: type of service is now deprecated since this field is now used
     * for differentiate service, we initialize it at 0 to say that we use 
     * BEST-EFFORT
     */
    ipHeader->ip_tos = 0x00;
    ipHeader->ip_len = ipHeader->ip_hl + len;
    //flags 0x02 means don't fragment
    ipHeader->ip_off = 0x0200;
    ipHeader->ip_ttl = MAX_TTL_DEF;
    ipHeader->ip_sum = 0;
    
    //set the source
    setSource();
    //END
    
    ipTimeOpt = new ip_timestamp;
    
    //BEGIN initialization of the ip timestamp structure
    
    //code is timestamp
    ipTimeOpt->ipt_code = IPOPT_TS;
    /* NOTE: the flag field must be prespecified because we specify the 
     * possible ips from which receive the timestamp before
    */
    ipTimeOpt->ipt_flg = IPOPT_TS_PRESPEC;
    
    ipTimeOpt->ipt_len = 32;
    ipTimeOpt->ipt_oflw = 0;
    
    //start of the timestamp field
    ipTimeOpt->ipt_ptr = START_TS;
}

//set the source address for the IP
void ipClass::setSource() {
    
    //retrieve external ip address of the source host 
    /*struct ifaddrs * ifAddrStruct = NULL;
    struct ifaddrs * ifa = NULL;
    void * tmpAddrPtr = NULL;

    getifaddrs(&ifAddrStruct);
    
    //scan the list of assigned addresses 
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa ->ifa_addr->sa_family == AF_INET) { // check if it is IP4
            tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
        }
    }
    
    //copy the addres in the network format into the ip header
    memcpy(&ipHeader->ip_src, tmpAddrPtr, sizeof(in_addr));
    
    freeifaddrs(ifAddrStruct);
    */
}

//set the destination address in the IP header
void ipClass::setDest(char* addr){
    
    if(addr != NULL) 
        inet_pton(AF_INET, addr, &ipHeader->ip_dst);
    
}

//set the timestamp targets
void ipClass::setTimestampTarget(char* addr) {
    
    for(int i=0; i<8; i++) {
        
        inet_pton(AF_INET, addr, &ipTimeOpt->data[i]);
        i++;
        //set the timestamp value to 0
        ipTimeOpt->data[i] = 0;
        
    }
}

//get the number of timestamps put by the router on the path
int ipClass::getTimestampNumbers(){
    
    int number = 0;
    
    for(int i=1; i<8; i+=2) {
        
        if(ipTimeOpt->data[i] != 0)
            number++;
        
    }
    
    return number;
}

//ip checksum
uint16_t ipClass::setChecksum() {} //TODO

//set protocol above IP (above is referred to the transmission OSI view)
void ipClass::setProtocol(int proto) {
    ipHeader->ip_p = proto;
}

/* NOTE: since the ip header and the timestamp option are represented as two
 * separate data structure is important for our purposes to pack them into
 * a single structure to be put on the top of the packet
 */
uint16_t* ipClass::pack() {
    
    /* IP_TS_LENGTH is referred to long (32 bits) here we use 16 bits, more
     * useful to compute the checksum also*/
    uint16_t ipPacked[IP_TS_LENGTH * 2];
    
    //before packing set the checksum
    setChecksum();
    memcpy(ipPacked, ipHeader, 10);
    memcpy(ipPacked+10, ipTimeOpt, 9);
    
    return ipPacked;
}

ipClass::~ipClass() {
    
    delete ipHeader;
    delete ipTimeOpt;
    
}