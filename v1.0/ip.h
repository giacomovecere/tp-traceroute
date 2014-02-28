/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */
#include "trace_header.h"
#include <ifaddrs.h>

class ipClass {
    
    ip* ipHeader;
    ip_timestamp* ipTimeOpt;
    
    //private functions
    void setSource();
    uint16_t setChecksum();
    
public:
    ipClass(int len, int id_start);
    void setDest(char*);
    void setTimestampTarget(char*);
    int getTimestampNumbers();
    void setProtocol(int p);
    uint16_t* pack();
    ~ipClass();
};

class ipManager {
    
public:
    
    /* param: destAddr, TimestampAddr
       returns the ip struct */
    uint16_t* prepareHeader(char*, char* = 0);
};