#include "ip.h"

//prepare the header UDP 
uint16_t* ipManager::prepareHeader(char* dest, char* time) {
    
    //a way to generate a sequence number that doesn't start from 0
    ipClass ipHdr = new ipClass();
    
    //set the protocol
    if(time == 0)  {
        time = dest;
        ipHdr.setProtocol(ICMP_PROTOCOL);
    }
    else
        ipHdr.setProtocol(UDP_PROTOCOL);
    ipHdr.setDest(dest);
    ipHdr.setTimestampTarget(time);
    
    uint16_t* packetIP = ipHdr.pack();
    
    return packetIP;
}