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

class ipClass {
    
public:
    setDest(char*);
    setSource(char*);
    setTimestampTarget(char*);
    int getTimestampNumbers();
};

class ipManager {
    
public:
    /* param: destAddr, TimestampAddr
       returns the ip struct */
    ip* prepareHeader_UDP(char*, char*);
};