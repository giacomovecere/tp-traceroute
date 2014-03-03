#include "ip.h"

ipManager::ipManager() {
    //a way to generate a sequence number that doesn't start from 0
    ip_hdr = new ipClass();
}

//prepare the header UDP 
uint8_t* ipManager::prepareHeader(char* dest, char* time) {
    
    //set the protocol
    if(time == 0)  {
        time = dest;
        ip_hdr->setProtocol(ICMP_PROTOCOL);
    }
    else
        ip_hdr->setProtocol(UDP_PROTOCOL);
    ip_hdr->setDest(dest);
    ip_hdr->setTimestampTarget(time);
    
    uint8_t* packetIP = ip_hdr->pack();
    
    /*cout<<"ipManager:\n";
    for(int i=0; i<IP_TS_LENGTH * 4; i++) 
        cout<<(int)packetIP[i]<<'\t';
    cout<<endl<<endl;
    */
    return packetIP;
}