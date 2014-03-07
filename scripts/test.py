#!/usr/bin/env python3 

import subprocess
import threading
import psycopg2

#
class myThread (threading.Thread):
    # costructor
    def __init__(self, threadID, dest_ip):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.dest_ip = dest_ip
    # run method
    def run(self):
        print ("Starting " + str(self.threadID))
        call_tp(self.dest_ip, str(self.threadID))
        print ("Exiting " + str(self.threadID))

# thread main that call tp-traceroute with dest_ip as argoument
def call_tp(dest_ip,id_thread):
    print("tp-traceroute " + id_thread + " ip: " + dest_ip)
    subprocess.call(["../v1.0/tp-traceroute",dest_ip])

# read destination from database and perform tp-traceroute  
# connection to database
conn = psycopg2.connect("dbname=results user=postgres hostaddr=127.0.0.1 port=5432")
cur = conn.cursor()
cur.execute("SELECT ip_dest FROM destinations;")
destinations = cur.fetchall()
cur.close()
conn.close()

# create threads
for i in range(0,len(destinations)-1):
    data = destinations[i]
    #try:
    #    m_thread = myThread(i,data[0])
    #    m_thread.start()
    #except:
    #    print ("Error: unable to start thread")
    call_tp(data[0],str(i))

#end#