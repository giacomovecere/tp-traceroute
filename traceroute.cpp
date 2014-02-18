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

void tv_sub(timeval *out, timeval *in) {
	if ( (out->tv_usec = in->tv_usec - out->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec = in->tv_sec - out->tv_sec;
}

 /* function that finds if there is a packet in the list with a checksum that is equal to 
 * the one that is passed on the function 
bool find_checksum(uint16_t checksum, list<addr>::iterator start, list<addr>::iterator end)
{
        addr* element;
        list<addr>::iterator p;
        
        // empty list
        if(start == end)
                return false;

        for(p = start; p != end; p++){
                *element = *p;
                if(element->checksum == checksum)
                        return true;
        }
        return false;
}*/

/* Finds if there is an element with the given checksum and updates the timeval field */
bool change_timeval(addr* address, 
                    list<addr>::iterator start, list<addr>::iterator end){
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

traceroute::traceroute(uint16_t s_port) {
    src_port = s_port;
}

/* computes the traceroute to the destination: 'ip_address'
 * 'max_ttl' indicates the max value for the TTL
 * 'dest_port_ini' is the first value of the destination port. It is going to be incremented 
 * for finding one from which the router along the path will reply */
bool traceroute::trace(char* ip_address, int max_ttl, uint16_t dest_port_ini) {
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
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;
	
    /* this variable is used to state which will be the port to be used for the 
     * n step, when n>1 */
    uint16_t receive_port = 0;
            
    //vector of used dest port, useful for the icmp
    uint16_t dest_port;
    addr address_vector[N_PROBE_DEF]; //to use when I send more probes
    addr address_ttl_1;         //address when ttl=1
    
    // udpManager to manage the udp packets are going to be sent
    udpManager uManager = udpManager(src_port);
    
    FD_SET(socket, &master);
    read_fds = master;
    for(ttl = 1; ttl < max_ttl && done == false; ttl++) {
		#ifdef _DEBUG
			cout<<"TTL = "<< ttl <<endl;
		#endif
		
        /* NOTE: first of all send the packets to the destination*/
        
        // If ttl = 1, it sends 'N_PROBE_DEF' probes with different dest. ports
        if(ttl == 1) {
            for(int i = 0; i < N_PROBE_DEF; i++) {  
				/*#ifdef _DEBUG
					cout<<"N_PROBE-for. i = "<< i <<" ttl = "<< ttl <<endl;
				#endif*/
							 
                dest_port = dest_port_ini + i;
                // each packet has different payload and different dest. port
                uManager.send(ip_address, dest_port, ttl, payload++, 1, &address_ttl_1);
                array_ip_list[ttl].push_back(address_ttl_1);
            }
        }
        else {
			if(receive_port != 0) {
				#ifdef _DEBUG
					cout<<"Sending "<< (int)N_PROBE_DEF <<" packets to "<< receive_port <<" destination port"<<endl<<endl;
				#endif
				
				/* it send 'N_PROBE_DEF UDP packets to the destination
				 * each packet has different payload but same dest. port 
                 * return false if an error has occured */
				result = uManager.send(ip_address, receive_port, ttl, payload, N_PROBE_DEF, address_vector);
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
		}
        
        //receive port set to 0 to check if any ICMP message arrives
        receive_port = 0;
        
        // loop until we receive all of the 'N_PROBE_DEF' packets or the time expires
        while(packets_in_time) {
            
            //NOTE: now to the receive of the icmp packets
            if(select(fdmax+1, &read_fds, NULL, NULL, &timeout) == -1) {
                cerr<<"select error\n";
                exit(1);
            }
            if(FD_ISSET(socket, &read_fds)) {
                //receive the icmp packet and a variable 'type' for the type of the router reached
                packet_received = iManager.recv(&type); 
                
                //received the structure with all the fields we are interested in
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
                        array_ip_list[ttl].end()))
                        
                        pcks_received++;
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
                //if we did not receive any packets we need to restart the traceroute (with another dest. port)
                if(pcks_received == 0) {
                    cout<<"No response messages along the path: TRACEROUTE FAILED! \n\n";
                    return false;
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

/* Returns the pointer of the array that contains the lists of the 'addr' elements */
list<addr>* traceroute::getArrayList() {
	return array_ip_list;	
}

/* Destroyer */
traceroute::~traceroute() {
    for(int i=0; i < MAX_TTL_DEF; i++) {
        if(array_ip_list[i].begin() == array_ip_list[i].end())
            break;
        
        array_ip_list[i].clear();
    }
}

// Redefinition of the output operator for printing the elements of the list stored
void traceroute::print()  {
    
    list<addr>* tmp;
    list<addr>::iterator p, q;
    tmp = array_ip_list;
    
    //scan the array of list
    for(int i = 1; i < MAX_TTL_DEF; i++) {
        p = tmp[i].begin();
        q = tmp[i].end();
        
        if(tmp[i].empty() == true) break;
        
        while (p != q) {
            if(p->ret) {
                fprintf(stdout, "IP Address: %s\n", p->ip);
                break;
            }
            p++;
        }
        
        p = tmp[i].begin();
        q = tmp[i].end();
        
        //scanning the list
        while(p != q) {
            
            //fprintf(stdout, "IP Address: %s\n", p->ip);
            //check if the packet has received response
            if(p->ret) {
                float rtt = p->time.tv_sec * 1000.0 +
                            p->time.tv_usec / 1000.0;
                // formatted print of the rtt
                fprintf(stdout, "%4.3f ms ", rtt);
            }
            else 
                fprintf(stdout, "   *    ");
            p++;
        }
        fprintf(stdout, "\n\n");
    }
} 
