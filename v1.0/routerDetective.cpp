/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 */

#include "routerDetective.h"

#define WAIT_FOR_ECHO_REPLY     0
#define WAIT_FOR_PORT_UNREACH   1

//Constructor of the class: sets the pointer of the array and its the last position  
routerDetective::routerDetective(list<addr>* list, int last) {
      array_list = list;
      last_position = last;
}

/*Coordinates the classification of hops discovered by traceroute towards the destination.
     Hops are classified as: NON CLASSIFIABLE, ON PATH or THIRD PARTY*/
bool routerDetective::thirdPartyDetection(uint16_t s_port, uint16_t dest_port, char* destAddr) {
    list<addr>::iterator p;
    //icmpManager icmp_m = icmpManager(s_port);
    int echo_resp, class_ret;
    
    //for each elements of the array that contains hops discovered by traceroute
    for(int i=1; i<= last_position; i++)
    {
        //empty list
        if(array_list[i].empty()) {
            cerr<<"Error: Empty element in the array "<<endl;
            return false;
        }
        
        for(p = array_list[i].begin(); p != array_list[i].end(); p++){
           
            /* The intermediate hop has provided a response to the traceroute
             * In the traceroute, for each hop, we sent 3 probes
             * Here we consider only one element of these */
            if(p->ret == true) {
                //char* hop_address = new char[15];
                //strncpy(hop_address, p->ip, strlen(p->ip)+1);
                echo_resp = echoReqReply(p->ip, s_port);
                
                //delete hop_address;
                #ifdef _DEBUG
                    cout<<"send "<<i<<" done. The response is "<<echo_resp<<endl;
                #endif
                
                switch(echo_resp) {
                    // Timeout expired
                    case -1:
                        p->classification = NO_RESPONSE;
                        break;
                    // the hope is not classifiable
                    case 0:
                        p->classification = NON_CLASSIFIABLE;
                        break;
                        
                    //the hope is classifiable
                    case 1:
                        class_ret = hopsClassificability(s_port, dest_port, destAddr, p->ip);
                        
                        //Timeout expired
                        if(class_ret == -1) {
                            p->classification = NO_RESPONSE_UDP;
                        }
                        else 
                            if(class_ret == 1) 
                                p->classification = ON_PATH;
                            // class_ret == 0
                            else   
                                p->classification = THIRD_PARTY;
                        break;
                }
                break;
            }
        }
    }
    return true;
}

void writeDB(char* destAddr, char* ip, char* classification) {
    
    char sql[MAX_VALUE], insertion[MAX_VALUE];    
    PGconn *dbconn;
    dbconn = PQconnectdb("dbname = Results");
    if (PQstatus(dbconn) == CONNECTION_BAD) {
        printf("Unable to connect to database\n");
    }
    
    sprintf(sql, "%s", "INSERT INTO TRACES (IP_HOP, IP_DEST, CLASSIFICATION) VALUES");
    sprintf(insertion, "%s ('%s', '%s', '%s' );", sql, destAddr, ip, classification);
    PGresult *query;
    query = PQexec(dbconn, insertion);
    printf ("%s\n", PQgetvalue(query, 0, 1));
    PQfinish(dbconn);

}

/* Prints the elements of the list stored */
void routerDetective::print(char* destAddr)  {
    //database d = database();
	list<addr>* tmp;
    char in_class[10];
    list<addr>::iterator p, q;
    tmp = array_list;
    int counter = 1;
    FILE* f;
    char folder[30];
    strcpy(folder, (char*)"./outcomes/");
    strcpy(folder + 11, (const char*)destAddr);
    cout<<folder<<endl;
    f = fopen(folder, "w");
    
    //scan the array of list
    for(int i = 1; i <= last_position; i++) {
        p = tmp[i].begin();

        cout<<counter;
        int j;
        for(j=0; j < N_PROBE_DEF; j++) {
            if(p->ret == true) {
                cout<<" ("<<p->ip<<") \t";
                fprintf(f, "%s\t", p->ip);
                
                switch(p->classification) {
                    case NO_RESPONSE:
                        cout<<" NO RESPONSE"<<endl;
                        fprintf(f, "NO_RESPONSE\n");
                        sprintf(in_class, "%s", "NO_RESPONSE");
                        break;
                    case NON_CLASSIFIABLE:
                        cout<<" NON-CLASSIFIABLE "<<endl;
                        fprintf(f, "NON_CLASSIFIABLE\n");
                        sprintf(in_class, "%s", "NON_CLASSIFIABLE");
                        break;
                    case NO_RESPONSE_UDP:
                        cout<<" NO RESPONSE - UDP "<<endl;
                        fprintf(f, "NO_RESPONSE-UDP\n");
                        sprintf(in_class, "%s", "NO_RESPONSE-UDP");
                        break;
                    case ON_PATH:
                        cout<<" ON PATH "<<endl;
                        fprintf(f, "ON_PATH\n");
                        sprintf(in_class, "%s", "ON_PATH");
                        break;
                    case THIRD_PARTY:
                        cout<<" THIRD PARTY "<<endl;
                        fprintf(f, "THIRD_PARTY\n");
                        sprintf(in_class, "%s", "THIRD_PARTY");
                        break;
                }
                writeDB(destAddr, p->ip, in_class);
                sprintf(in_class, "%s", "");
                break;
            }
            p++;
        }
        if(j == N_PROBE_DEF) {
            cout<<" * \t * \t *"<<endl;
        }
                
        counter++;
        cout<<endl;
    }
        fclose(f);
} 

// Sends an ICMP echo request to each intermediate hop and receives an icmp echo reply
int echoReqReply(char* destAddr, uint16_t s_port) {
   
    char payload[LENGTH_PAYLOAD];
    icmpManager icmpM = icmpManager(s_port);
    int socket = icmpM.getSocket(); //get the file descriptor which needs to be read
    int fdmax;  //max number of file descriptor
    fd_set master, read_fds;
    int num_ts, ret;
    
    fdmax = socket;
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;
    
    
    FD_SET(socket, &master);
    read_fds = master;
        
    memset(payload, 0, LENGTH_PAYLOAD);

    // Sends an icmp echo request
    ret = icmpM.tpSend(payload, destAddr);
    if(ret == 0) {
        cerr<<"Error: tpSend error"<<endl;
        exit(EXIT_FAILURE);
    }
                
    if(select(fdmax+1, &read_fds, NULL, NULL, &timeout) == -1) {
        cerr<<"select error\n";
        exit(EXIT_FAILURE);
    }
    
    if(FD_ISSET(socket, &read_fds)) {
        /* Receives an icmp echo response from an intermediate hop and check 
            the number of timestamps that are in the packet */
        num_ts = icmpM.tpRecv(WAIT_FOR_ECHO_REPLY); 
        
        //the hop is not classifiable
        if(num_ts < 1 || num_ts > 3)
            return 0;
        //the hope is classifiable if the number of timestamps received is 1, 2 or 3
        else
            return 1;
    }
    else {
        #ifdef _DEBUG
            cout<<"Timeout expired"<<endl;
        #endif
            
        return -1;
    }
}

/*Sends UDP probes to classifiable hops and receives an icmp port unreach from intermediate hops*/
int hopsClassificability(uint16_t s_port, uint16_t dest_port, char* destAddr, char* ts_ip){
    list<addr>::iterator p;
    icmpManager icmpM = icmpManager(s_port);
    udpRawManager* udpRawManag = new udpRawManager(s_port, dest_port); ;
    int num_ts, ret;
    char payload[LENGTH_PAYLOAD];
    int fdmax;  //max number of file descriptor
    fd_set master, read_fds;
    int socket = icmpM.getSocket(); //get the file descriptor which needs to be read
    
    fdmax = socket;
    
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SELECT;
    timeout.tv_usec = 0;
    
    FD_SET(socket, &master);
    read_fds = master;
    
    memset(payload, 0, LENGTH_PAYLOAD);

    //Sends udp probe to a classifiable hop
    ret = udpRawManag->tpSend(destAddr, ts_ip, payload);
    if(ret == 0) {
        cerr<<"Error: tpSend error"<<endl;
        delete udpRawManag;
        return -1;
    }
    delete udpRawManag;

    if(select(fdmax+1, &read_fds, NULL, NULL, &timeout) == -1) {
        cerr<<"select error\n";
        exit(EXIT_FAILURE);
    }
        
    if(FD_ISSET(socket, &read_fds)) {
        /* Receives an icmp echo response from an intermediate hop and check 
            the number of timestamps that are in the packet */
        num_ts = icmpM.tpRecv(WAIT_FOR_PORT_UNREACH); 
        
        //the hop is a TP
        if(num_ts < 1)
            return 0;
        //the hop is OP
        else
            return 1;
    }
    else {
        #ifdef _DEBUG
            cout<<"Timeout expired"<<endl;
        #endif
            
        return -1;
    }
}

   
       
	
