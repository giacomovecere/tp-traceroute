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

//#include "unp.h"
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
#include <sys/time.h>

#define MAX_TTL_DEF 30
#define N_PROBE_DEF 3

using namespace std;


struct addr {
    char ip[20];
    struct timeval time[N_PROBE_DEF];
    uint16_t checksum[N_PROBE_DEF];
    addr* punt;
};

