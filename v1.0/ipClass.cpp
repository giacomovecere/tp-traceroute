/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
#include "ip.h"

//this is the constructor of the ip class, we initialize all the constants fields
/* NOTE: as stated in the RAW(7) some of the fields are filled by the kernel hence 
 * there may be the interface of the calling to the function, but it will not 
 * be implemented since the hardware provides the answer to this question
 * 
 * NOTE: ALL THE IP FIELDS MUST BE IN NETWORK ORDERING
 */
ipClass::ipClass(){
    
    ipHeader = new ip;
    
    
    //BEGIN initialization of the IP header
    /* the length of the header needs to be computed:
     * 5 is the standard length
     * timestamp option takes 9 * 4 bytes
     * hence ip header length is 14 bytes
    */
    ipHeader->ip_hl = IP_TS_LENGTH;
    //we use only IPv4
    ipHeader->ip_v = IPv4;
    /* NOTE: type of service is now deprecated since this field is now used
     * for differentiate service, we initialize it at 0 to say that we use 
     * BEST-EFFORT
     */
    ipHeader->ip_tos = 0x00;
    ipHeader->ip_id = (getpid() & 0xffff) | 0x8000;
    //flags 0x4000 means don't fragment
    ipHeader->ip_off = htons(0x4000);
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
    
    ipTimeOpt->ipt_len = 36;
    ipTimeOpt->ipt_oflw = 0;
    
    //start of the timestamp field
    ipTimeOpt->ipt_ptr = 5;//START_TS;
    //END
}

/* @Purpose: constructor of an ip class basing on the received IP
 * @Parameters:
 *              (IN) an ip header with timestamp options
 */
ipClass::ipClass(uint8_t* iphdr) {
    ipHeader = new ip;
    ipTimeOpt = new ip_timestamp;
    //copy the first 20 bytes in the ipheader
    memcpy(ipHeader, iphdr, 20);
    //copy the other bytes in the timestamp option
    memcpy(ipTimeOpt, iphdr+20, 36);
}

/* @Purpose: Set the source address of the packet
 * NOTE: this is done by getting all the IP addresses associated to our machine
 * and then selecting only the first IPv4
 */
void ipClass::setSource() {
    
    //retrieve external ip address of the source host 
    ifaddrs * ifAddrStruct = new ifaddrs;
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
    
}

//set the destination address in the IP header
void ipClass::setDest(char* addr){
    
    if(addr != NULL) {
        int ret = inet_pton(AF_INET, addr, &ipHeader->ip_dst);
        if(ret != 1) {
            cout<<"ipClass::setDest error, ret = "<<ret<<endl;
            exit(EXIT_FAILURE);
        }
    }
    
}

/* NOTE: the timestamp buffer (the 8 bytes after the option header) 
 * is formed by 4 couple of 32 bits field, the first field of the couple 
 * represents the address from which we want to receive the timestamp, the
 * second field represents the effective timestamp and will be filled by routers
 */
/* @Purpose: set the timestamp target
 * @Parameters: 
 *              (IN) an address in host format
 */
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
    
    //scan the timestamp buffer and check if the timestamp field is set or not
    for(int i=1; i<8; i+=2) {
        
        if(ipTimeOpt->data[i] != 0)
            number++;
        
    }
    
    return number;
}

//ip checksum
void ipClass::setChecksum() {}

//set protocol above IP (above is referred to the transmission OSI view)
void ipClass::setProtocol(int proto) {
    ipHeader->ip_p = proto;
}

/* NOTE: since the ip header and the timestamp option are represented as two
 * separate data structure is important for our purposes to pack them into
 * a single structure to be put on the top of the packet
 */
/* @Purpose: pack the whole ip header with 
 *      timestamp option into a single buffer
 * @Returns: the address of the buffer
 */
uint8_t* ipClass::pack() {
    
    /* IP_TS_LENGTH is referred to long (32 bits) here we use 16 bits, more
     * useful to compute the checksum also*/
    uint8_t* ipPacked = new uint8_t[IP_TS_LENGTH * 4];
    
    //before packing set the checksum
    setChecksum();
    memcpy(ipPacked, (void*)ipHeader, 20);
    memcpy(ipPacked + 20, (void*)ipTimeOpt, 36);
    
    return ipPacked;
}

//destroyer
ipClass::~ipClass() {
    delete ipHeader;
    delete ipTimeOpt;
}