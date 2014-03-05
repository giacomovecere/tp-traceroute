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

traceroute::traceroute(uint16_t s_port, int max_ttl) {
    src_port = s_port;
    last_position = 0;
    ttl_max = max_ttl;
    array_ip_list = new list<addr> [ttl_max];
}

/* computes the traceroute to the destination: 'ip_address'
 * 'max_ttl' indicates the max value for the TTL
 * 'dest_port_ini' is the first value of the destination port. It is going to be incremented 
 * for finding one from which the router along the path will reply */
bool traceroute::trace(char* ip_address, uint16_t* dest_port_set) {
    int payload = 1; //initial payload
    int ttl;
    int pcks_received = 0;
    
    //NOTE this list part will be used to storage the info received
    //and to print them eventually
    addr* packet_received;
    list<addr>::iterator p_iterator;
    
    //create a new icmpManager and manage the file descriptor associated
    icmpManager iManager = icmpManager(src_port);
    int socket = iManager.getSocket(); //get the file descriptor which needs to be read
    int fdmax;  //max number of file descriptor
    fd_set master, read_fds;
    fdmax = socket;
    bool packets_in_time = true, done = false, result;
    int type; 
    int go_ahead = N_TIMES_TO_GO_AHEAD;
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;
	
    /* this variable is used to state which will be the port to be used for the 
     * n step, when n>1 */
    uint16_t receive_port = 0;
    uint16_t dest_port_ini = *dest_port_set;
            
    //vector of used dest port, useful for the icmp
    uint16_t dest_port;
    addr address_vector[N_PROBE_DEF]; //to use when I send more probes
    addr address_ttl_1;         //address when ttl=1
    addr no_response;
    
    // udpManager to manage the udp packets are going to be sent
    udpHLManager uManager = udpHLManager(src_port);
    
    FD_SET(socket, &master);
    read_fds = master;
    for(ttl = 1; ttl < ttl_max && done == false; ttl++) {
		#ifdef _DEBUG
			cout<<"TTL = "<< ttl <<endl;
		#endif
            
        last_position = ttl;
		
        /* NOTE: first of all send the packets to the destination*/
        
        // If ttl = 1, it sends 'N_PROBE_DEF' probes with different dest. ports
        if(ttl == 1) {
            for(int i = 0; i < N_PROBE_DEF; i++) {
							 
                dest_port = dest_port_ini + i;
                // each packet has different payload and different dest. port
                uManager.send(ip_address, dest_port, ttl, payload++, 1, &address_ttl_1);
                array_ip_list[ttl].push_back(address_ttl_1);
            }
        }
        else {
            // Sets the default destination port, based on the response messages
            if(ttl == 2) {
                // At least one ICMP message has arrived
                if(receive_port != 0)
                    *dest_port_set = receive_port;
                else
                    *dest_port_set = dest_port;
            }
            #ifdef _DEBUG
                cout<<"Sending "<< (int)N_PROBE_DEF <<" packets to "<< *dest_port_set <<" destination port"<<endl<<endl;
            #endif
            
            /* sends 'N_PROBE_DEF UDP packets to the destination
             * each packet has different payload but same dest. port 
             * return false if an error has occured */
            result = uManager.send(ip_address, *dest_port_set, ttl, payload, N_PROBE_DEF, address_vector);
            if(result == false) {
                return false;
            }
            
            // Substancial change of the payload from one group of probes to another
            payload += 20;  
        
            for(int i = 0; i < N_PROBE_DEF; i++) {
                // it puts the 'addr' elements filled by the send method in the list
                array_ip_list[ttl].push_back(address_vector[i]);
            }
		}
        
        // loop until we receive all of the 'N_PROBE_DEF' packets or the time expires
        while(packets_in_time) {
            
            //NOTE: now to the receive of the icmp packets
            if(select(fdmax+1, &read_fds, NULL, NULL, &timeout) == -1) {
                cerr<<"select error\n";
                exit(1);
            }
            if(FD_ISSET(socket, &read_fds)) {
                //receive the icmp packet and a variable 'type' for the type of the router reached
                packet_received = iManager.traceRecv(&type); 
                
                /* received the structure with all the fields we are interested in.
                   'receive_port' is set just one time with the port of the reply */
                if (receive_port == 0) 
                    receive_port = iManager.getDestPort(); 
                
                //check if type is correct for my purposes
                if(type == INTERMEDIATE_ROUTER || type == FINAL_DESTINATION) {
                    #ifdef _DEBUG
                        fprintf(stdout, "Checksum received: %4x from (%s)\n", 
                                packet_received->checksum, packet_received->ip);
                        cout<<endl;
                    #endif		    
                    /* modify the element in the list only if the packet received belongs to that 
                     * TTL "slot time" */
                    if(change_timeval(packet_received, array_ip_list[ttl].begin(), 
                        array_ip_list[ttl].end()) == true)
                        pcks_received++;
                    
                    // Reset of the variable because he have just received a packet
                    go_ahead = N_TIMES_TO_GO_AHEAD;
                }
                
                if(type == -1) 
                    cout<<"Error receiving the packet\n";
                
                if(pcks_received == N_PROBE_DEF){ 
                    // if the destination has been reached, traceroute can stop
                    if(type == FINAL_DESTINATION) { 
                        done = true;
                    }
                    break;
                }
            }
            
            // The case of 'Time expired'
            else {
                if(pcks_received == 0) {
                    #ifdef _DEBUG
                        cout<<"Timeout expired"<<endl;
                    #endif
                    /*if we did not receive any response packets for 'go_ahead' times consecutively 
                      we need to restart the traceroute (with another dest. port) */
                    go_ahead--;                    
                    if(go_ahead == 0) {
                        cout<<"No response messages along the path for "<< N_TIMES_TO_GO_AHEAD <<" times consecutively: TRACEROUTE FAILED! \n\n";
                        return false;
                    }          
                    
                    // add an element to 'array_ip_list' to signal no response packet has arrived
                    no_response.ret = false;
                    array_ip_list[ttl].push_back(no_response);
                    
                    packets_in_time = false;
                }
                else {
                    if(type == FINAL_DESTINATION) { 
                        done = true;
                    }
                    
                    packets_in_time = false;
                }
            }
        }
        
        // resetting of variables for new cycle
        packets_in_time = true;
        pcks_received = 0;
        timeout.tv_sec = TIMEOUT_SELECT;
        timeout.tv_usec = 0;
        type = 2;
    }
    
    return true;   
}

void traceroute::resetObj(uint16_t s_port, int max_ttl) {
    src_port = s_port;
    ttl_max = max_ttl;
    last_position = 0;
}

/* Returns the pointer of the array that contains the lists of the 'addr' elements */
list<addr>* traceroute::getArrayList(int* l_pos) {
    *l_pos = last_position;
	return array_ip_list;	
}

/* Destroyer */
traceroute::~traceroute() {
    for(int i=0; i < last_position; i++) {
        if(array_ip_list[i].begin() == array_ip_list[i].end())
            break;
        
        array_ip_list[i].clear();
    }
    //delete array_ip_list;
}

/* Prints the elements of the list stored */
void traceroute::print()  {
    
    list<addr>* tmp;
    list<addr>::iterator p, q;
    tmp = array_ip_list;
    int counter = 1;
    
    //scan the array of list
    for(int i = 1; i <= last_position; i++) {
        p = tmp[i].begin();
        
        cout<<counter;
        
        for(int j=0; j < N_PROBE_DEF; j++) {
            if(p->ret == true) {
                cout<<" ("<<p->ip<<") \t";
                break;
            }
            
            p++;
        }
        
        p = tmp[i].begin();
        
        //scanning the list
        for(int j=0; j < N_PROBE_DEF; j++) {
            //check if the packet has received response
            if(p->ret == true) {
                float rtt = p->time.tv_sec * 1000.0 +
                            p->time.tv_usec / 1000.0;
                // formatted print of the rtt
                fprintf(stdout, " %4.3f ms ", rtt);
            }
            else 
                cout<<"   *    ";
            
            p++;
        }
        counter++;
        cout<<endl<<endl;
    }
} 

/* Performs the subtraction between the structure 'in' and 'out' */
void tv_sub(timeval *out, timeval *in) {
    if ( (out->tv_usec = in->tv_usec - out->tv_usec) < 0) { /* out -= in */
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec = in->tv_sec - out->tv_sec;
}

/* Finds if there is an element with the given checksum and updates the timeval field */
bool change_timeval(addr* address, list<addr>::iterator start, list<addr>::iterator end){
        list<addr>::iterator p;
        
        // empty list
        if(start == end)
                return false;

        for(p=start; p!= end; p++){
                if(p->checksum == address->checksum){
                    p->ret = true;
                    tv_sub(&p->time, &address->time);
                    memcpy(p->ip, address->ip, LENGTH_IP_ADDRESS);
                    return true;
                }
        }
        return false;
}

