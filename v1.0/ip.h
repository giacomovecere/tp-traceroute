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
    
    //constructor (NOTE for further details see the ipClass.cpp) 
    ipClass();
    ipClass(uint8_t*);
    //Destroyer
    ~ipClass();
    void setDest(char*);
    void setTimestampTarget(char*);
    int getTimestampNumbers();
    void setProtocol(int p);
    in_addr getSource() {return ipHeader->ip_src;};
    in_addr getDest() {return ipHeader->ip_dst;};
    
    //pack the whole ip header with timestamp option into a single buffer
    uint8_t* pack();
};

class ipManager {
    
    ipClass* ip_hdr;
    
public:
    
    //constructor
    ipManager();
    ipManager(uint8_t*);
    //destroyer
    ~ipManager();
    
    in_addr getSource() {return ip_hdr->getSource();};
    in_addr getDest() {return ip_hdr->getDest();};
    int getTimestamps() {return ip_hdr->getTimestampNumbers();};
    
    //prepare the ipHeader according to timestamp option
    uint8_t* prepareHeader(char*, char* = 0);
};