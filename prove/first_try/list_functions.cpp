list<addr> array[MAX_TTL_DEF]
addr* elem;
list<addr>::iterator p_iterator;

/* Insert an element */
array[ttl].push_back(elem);

/*First element of the list */
p_iterator= array[ttl].begin();

/*Last element of the list */
p_iterator = array[ttl].end();



/* function that find a given checksum in the list */

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

bool change_timeval(struct timeval t, uint16_t checksum, list<addr>::iterator start, list<addr>::iterator end)
{
	addr* element;
	list<addr>::iterator p;
	
	if(start.empty())
		return false;

	for(p=start; p!= end; ++p){
		element = *p;
		if(element->checksum == checksum){
			element->ret = true;
			element->(time->tv_sec) = (t->(time->tv_sec)) - (element->(time->tv_sec));
			element->(time->tv_nsec) = (t->(time->tv_nsec)) - (element->(time->tv_nsec));
			return true;
		}
	}
	return false;
}

