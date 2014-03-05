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

ipManager::ipManager() {
    //a way to generate a sequence number that doesn't start from 0
    ip_hdr = new ipClass();
}

ipManager::ipManager(uint8_t* iphdr) {
    ip_hdr = new ipClass(iphdr);
}

/* @Purpose: prepare the ip header with the destination address
 *          and the addresses from which we want to receive the
 *          the timestamp option
 * @Parameters:
 *      (IN): first parameter is the destination address
 *            second parameter is the timestamp address
 *            both are in host format
 * @Returns: a buffer that contains the whole IP header 
 *           including timestamp option
 */
     
uint8_t* ipManager::prepareHeader(char* dest, char* timeStampTarget) {
    
    //set the protocol
    if(timeStampTarget == 0)  {
        timeStampTarget = dest;
        ip_hdr->setProtocol(IPPROTO_ICMP);
    }
    else
        ip_hdr->setProtocol(UDP_PROTOCOL);
    
    //set the needed addresses
    ip_hdr->setDest(dest);
    ip_hdr->setTimestampTarget(timeStampTarget);
    
    //do the pack
    uint8_t* packetIP = ip_hdr->pack();
    
    return packetIP;
}

//destroyer
ipManager::~ipManager() {
    delete ip_hdr;
}