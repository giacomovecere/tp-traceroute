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
#include <netinet/in.h>
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
#define N_PROBE_DEF 3
#define N_ATTEMPTS 3

using namespace std;

#ifndef TRACE_HEADER_H
#define TRACE_HEADER_H

struct addr {
    char ip[20];
    struct timeval time;
    uint16_t checksum;
    bool ret;
};

#endif /* TRACE_HEADER_H */
