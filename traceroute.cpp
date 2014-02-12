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

traceroute::traceroute(uint16_t s_port) {
    src_port = s_port;
    ip_list = 0;
}

addr* traceroute::trace(char* ip_address, int max_ttl) {
    int payload = 1; //Initial payload has to be defined
    int ttl;
    uint16_t dest_port_ini = 32768 + 666; //NOTE possible optimization
    
    /* NOTE we need to assign thos constant because we may receive less responses
     * of the number of probes sent hence we may need to change this number
     * in our case we decided to manage this number as follows:
     * if we send X probes (one for each port) 
     * and we recive N responses with N < X, for each port 
     * from which we received the answer we'll send in the next step X + (X%N) 
     * probes, hence the number of probes per port will be 
     * ceiling{[X + ceiling(X/N)] / X }   
     */
    int max_probe = N_PROBE_DEF;
    int probe_to_port = 1;
    
    //vector of used dest port, useful for the icmp
    uint16_t dest_port[N_PROBE_DEF];
    addr address_vector[N_PROBE_DEF]; //to use when I send more probes
    addr address_ttl_1;         //addres when ttl=1
    
    <create udp manager>
    <create as many ICMP as N_Probe_DEF>
    
    for(ttl=1; ttl < max_ttl; ttl++) {
        
        if(ttl == 1) {
            for(int i = 0; i < max_probe; i++ ) {
                
                dest_port[i] = dest_port_ini+i; //set the port
                address_ttl_1 = <single send of a single probe>
                <add address_ttl_1 in list>
                
            }
        }
        else {
            for(int i = 0; i < max_probe; i+probe_to_port) {
                address_vector = <send of probe_to_port probes to each dest_port>
                <scan the address_vector and put each address in the list>
            } 
        }
        
        //TODO ICMP receive and management 
        //NOTE remember to delete from the array the ports from which you don't receive 
        //answer
    }
    
    
    
            
    return ip_list;
}
