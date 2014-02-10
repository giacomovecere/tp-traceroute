/*
 * 
 * @Authors: Vecere Giacomo Razzano Alessia Piras Francesco La Marra Antonio
 * @Topic: UDP Paris-Traceroute to identify Third Party Addresses
 * USE OF IPv4
 * ONLY SUPERUSER CAN CREATE RAW DATAGRAMS HENCE TO RUN THE PROGRAM
 * YOU NEED TO BE SUPERUSER
 * 
 * Traceroute Header File
 * 
 */

struct address {
	char ip[20];
	struct timeval time[3];
	address* punt;
};

class traceroute {
	address* ip_list;
	uint16_t src_port; 
	
	public:
	
	traceroute(int);
	
	address* trace(char*, int, int);
	
};
