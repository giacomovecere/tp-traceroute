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

#include "unp.h"
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>

#define MAX_TTL_DEF 30
#define N_PROBE_DEF 3
