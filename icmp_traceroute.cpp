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
#include <list>
#include "trace_header.h"

bool find_checksum(uint16_t checksum, list<addr>::iterator start, list<addr>::iterator end)
{
        addr* element;
        list<addr>::iterator p;
        
        if(start.empty())
                return false;

        for(p=start; p!= end; ++p){
                element = *p;
                if(element->checksum == checksum)
                        return true;
        }
        return false;
}

/* function that changes the timeval given the checksum */

bool change_timeval(struct timeval t, uint16_t checksum, 
                    list<addr>::iterator start, list<addr>::iterator end){
        addr* element;
        list<addr>::iterator p;
        
        if(start.empty())
                return false;

        for(p=start; p!= end; ++p){
                element = *p;
                if(element->checksum == checksum){
                    element->ret = true;
                    element->time->tv_sec = 
                        (t->time->tv_sec) - (element->time->tv_sec);
                    element->time->tv_nsec = 
                        (t->time->tv_nsec) - (element->time->tv_nsec);
                    return true;
                }
        }
        return false;
}

void icmptrace() {
    int source_port;
    list<addr> array[MAX_TTL_DEF];
    addr* elem;
    list<addr>::iterator p_iterator;
    
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
    /* NOTE: type represents the type of host we've reached:
     * 1 port unreachable hence we reached the destination
     * 0 intermediate host
     * -1 error
     */
    int type;
    
    FD_SET(socket, &master);
    fdmax=socket;
    for(int x = 0; x < N_PROBE_DEF; i++ ) {
        read_fds=master;
        if(select(fdmax+1, &read_fds, NULL, NULL, &timer)==-1) {
            cerr<<"select error\n";
            exit(1);
        }
        if(FD_ISSET(socket, &read_fds)) {
            received=iManager.recv(&type); //receive the icmp packet
            
            //received the structure with all the fields I'm interested
            rec_port[j]=iManager.getPort();
            found=search(rec_port[j], port_array);
            if(found == false) {
                rec_port[j]=0;
                break;
            }
            
            //the received port is one of the actually used 
            else {
                //if error
                if(type == -1) {
                    cerr<<"error in the receive\n";
                    break; //there's an error
                }
                //if I reached an intermediate router
                if(type==0) {
                    //modify the correspondent elem in the list
                    change_timeval(received->time, received->checksum,
                        array[ttl].begin(), array[ttl].end());
                }
                if(type==1) {
                    change_timeval(received->time, received->checksum,
                        array[ttl].begin(), array[ttl].end());
                    max_ttl=ttl; //i need to exit from the for
                }
            }
        }
        //this means time expired
        else 
            break;
    }
    //update data structure for the next cycle
    for(int k = 0; k < N_PROBE_DEF; k++) {
        dest_port[k] = rec_port[k];
        rec_port[k] = 0;
    }
}


