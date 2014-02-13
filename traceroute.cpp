/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "traceroute.h"

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

traceroute::traceroute(uint16_t s_port) {
    src_port = s_port;
}

bool traceroute::trace(char* ip_address, int max_ttl) {
    int payload = 1; //Initial payload has to be defined
    int ttl;
    uint16_t dest_port_ini = 32768 + 666; //NOTE possible optimization
    uint16_t source_port;
    //makes it easy to count the number of received packets
    int n_receive = 0;
    
    //NOTE this list part will be used to storage the info received
    //and to print them eventually
    addr* elem;
    list<addr>::iterator p_iterator;
    
    //create a new icmpManager and manage the file descriptor associated
    icmpManager iManager = icmpManager(source_port);
    int socket = iManager.getSocket(); //get the file descriptor which need to be read
    int fdmax;  //max number of file descriptor
    fd_set master, read_fds;
    
    bool time_to_receive = true;
    
    /* this variable is used to state which will be the port to be used for the 
     * n step, when n>1
    */
    int rec_port = 0;
    
    //vector of used dest port, useful for the icmp
    uint16_t dest_port[N_PROBE_DEF];
    addr address_vector[N_PROBE_DEF]; //to use when I send more probes
    addr address_ttl_1;         //address when ttl=1
    
    // udpManager to manage the udp packets are going to be sent
    udpManager uManager = udpManager(src_port);
    
    for(ttl=1; ttl < max_ttl; ttl++) {
        n_receive = 0;
        time_to_receive = true;
        
        /* NOTE: first of all send the packets to the destination*/
        
        // If ttl = 1, it sends 'N_PROBE_DEF' probes with different dest. ports
        if(ttl == 1) {
            for(int i = 0; i < N_PROBE_DEF; i++) {               
                dest_port[i] = dest_port_ini + i;
                // each packet has different payload and different dest. port
                uManager.send(ip_address, dest_port[i], ttl, payload++, 1, &address_ttl_1);
                array[ttl].push_back(address_ttl_1);
            }
        }
        else {
            for(int i = 0; i < N_PROBE_DEF; i++) {
                if(rec_port != 0) {
                    uManager.send(ip_address, rec_port, ttl, payload++, 1, address_vector);
                    array[ttl].push_back(address_vector[j]);
                }
            }
        }
        
        while(time_to_receive) {
            
            //received all the messages
            if( n_receive == N_PROBE_DEF ) break;
            
            //NOTE: now to the receive of the icmp packets
            if(select(fdmax+1, &read_fds, NULL, NULL, &timer)==-1) {
                cerr<<"select error\n";
                exit(1);
            }
            if(FD_ISSET(socket, &read_fds)) {
                received=iManager.recv(&type); //receive the icmp packet
                
                //received the structure with all the fields I'm interested
                if (rec_port == 0) rec_port=iManager.getPort();
                
                if(type==0) {
                    //modify the correspondent elem in the list
                    change_timeval(received->time, received->checksum,
                        array[ttl].begin(), array[ttl].end());
                    n_receive++;
                }
                if(type==1) {
                    change_timeval(received->time, received->checksum,
                        array[ttl].begin(), array[ttl].end());
                    max_ttl=ttl; //i need to exit from the for
                    n_receive++;
                }
            }
            //this means time expired
            else 
                //if I didn't receive any packet I need to restart everything
                if(n_receive == 0) return false;
                else time_to_receive=false;
        }
    }
    
    return true;
            
    
}
