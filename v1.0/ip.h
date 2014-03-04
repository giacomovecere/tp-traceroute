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
    //Destroyer
    ~ipClass();
    void setDest(char*);
    void setTimestampTarget(char*);
    int getTimestampNumbers();
    void setProtocol(int p);
    in_addr getSource() {return ipHeader->ip_src;};
    in_addr getDest() {return ipHeader->ip_dst;};
    
    /* @Purpose: pack the whole ip header with 
     *      timestamp option into a single buffer
     * @Parameters:
     *      (OUT): returns the address of the buffer
     */
    uint8_t* pack();
};

class ipManager {
    
    ipClass* ip_hdr;
    
public:
    
    //constructor
    ipManager();
    //destroyer
    ~ipManager();
    
    in_addr getSource() {return ip_hdr->getSource();};
    in_addr getDest() {return ip_hdr->getDest();};
    
    /* @Purpose: prepare the ip header with the destination address
     *          and the addresses from which we want to receive the
     *          the timestamp option
     * @Parameters:
     *      (IN): first parameter is the destination address
     *            second parameter is the timestamp address
     *            both are in host format
     * @Returns: a buffer that contains the whole IP header 
     *          including timestamp option
     */
    uint8_t* prepareHeader(char*, char* = 0);
};