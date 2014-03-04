/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
#pragma once    /* Avoid multiple include of this file during compilation */
#include "trace_header.h"
#include <ifaddrs.h>

class ipClass {
    
    ip* ipHeader;
    ip_timestamp* ipTimeOpt;
    
    //private functions
    void setSource();
    void setChecksum();
    
public:
    ipClass();
    void setDest(char*);
    void setTimestampTarget(char*);
    int getTimestampNumbers();
    void setProtocol(int p);
    in_addr getSource() {return ipHeader->ip_src;};
    in_addr getDest() {return ipHeader->ip_dst;};
    uint8_t* pack();
    ~ipClass();
};

class ipManager {
    
    ipClass* ip_hdr;
    
public:
    ipManager();
    ~ipManager();
    in_addr getSource() {return ip_hdr->getSource();};
    in_addr getDest() {return ip_hdr->getDest();};
    /* param: destAddr, TimestampAddr
       returns the ip struct */
    uint8_t* prepareHeader(char*, char* = 0);
};