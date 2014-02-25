/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
#include "udp.h"

udpRawClass::udpRawClass(uint16_t src_port, char* dest_ip, uint16_t dest_port) {
    src_port = src_port;
    memcpy(this->dest_ip, dest_ip, sizeof(dest_ip));
    this->dest_port = dest_port;
    /* usa udphdr*/
    
}

 udpRawClass::setTs(char* ts_ip) {
        ip_hdr = prepareHeader(dest_ip, ts_ip);
}