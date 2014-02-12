//this is the icmp part of the traceroute
#include "icmp.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "trace_header.h"
void icmptrace() {
    <addr_list>
    
    icmpManager iManager =new icmpManager(source_port);
    int socket = iManager.getSocket(); //get the file descriptor which need to be read
    int fdmax;  //max number of file descriptor
    fd_set master, read_fds;
    int rec_port[N_PROBE_DEF];       //destination port to which the router responds
    for(int i=0; i<N_PROBE_DEF; i++)
        rec_port[i] = 0;
    
    
    //prapare the timer structure
    struct timeval timer;
    timer.tv_sec=3;
    timer.tv_nsec=0;
    addr* received;
    int j=0;    //iterator for the dest_port array 
    bool found;
    
    FD_SET(socket, &master);
    fdmax=socket;
    while(1) {
        read_fds=master;
        if(select(fdmax+1, &read_fds, NULL, NULL, &timer)==-1) {
            printf("Errore nella select %s \n", nome);
            exit(1);
        }
        for(i=0; i<=fdmax; i++)
            if(FD_ISSET(i, &read_fds)) {
                received=iManager.recv(); //receive the icmp packet
                
                //received the structure with all the fields I'm interested
                rec_port[j]=iManager.getPort();
                found=search(rec_port[j], port_array);
                if(found == false) {
                    rec_port[j]=0;
                    break;
                }
                else {
                    
                }
            }
  
    
    }
}


