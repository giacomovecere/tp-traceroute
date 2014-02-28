/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 * General Header
 * 
 */

#include <string.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <cstdlib>
#include <cstring>
#include <sys/time.h>
#include <list>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/in_systm.h>

#define MAX_TTL_DEF 30
#define TRACEROUTE_PORT 33434
#define N_PROBE_DEF 3
#define N_ATTEMPTS 3
#define LENGTH_PSEUDO_IP 12
#define LENGTH_IP_ADDRESS 20
#define INTERMEDIATE_ROUTER 0
#define FINAL_DESTINATION 1
#define TIMEOUT_SELECT 3
#define N_TIMES_TO_GO_AHEAD 5
#define NON_CLASSIFIABLE 0
#define ON_PATH 1
#define THIRD_PARTY 2
#define LENGTH_PAYLOAD 4
#define LENGTH_UDP_HEADER 8

using namespace std;

#ifndef TRACE_HEADER_H
#define TRACE_HEADER_H

/*
 * ip: ip address
 * time: timestamp
 * checksum: checksum of the packet
 * ret: it is set if we receive a reply to the sent packet
 * classification: classification of the router along the path to the destination
 */
struct addr {
    char ip[LENGTH_IP_ADDRESS];
    struct timeval time;
    uint16_t checksum;
    bool ret;
    int classification;
};

#endif /* TRACE_HEADER_H */
