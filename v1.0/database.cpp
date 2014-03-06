#include "database.h" 
database::database() {
    C = new Connection("dbname=Results user=postgres hostaddr=127.0.0.1 port=5432");
    if(!C.is_open()) {
        cerr<<"database errro: NOT OPENED\n";
    }
}

void database::insert(char* dest, char* ip, char* classification) {
    char* sql;
    char insertion[MAX_VALUE];
    sql = "INSERT INTO TRACES (IP_HOP, IP_DEST, CLASSIFICATION) VALUES";
    char* after="', '";
    char* end = "' );";
    char* before = "('";
    int length = 0;
    /*
    //prepare the insertion string
    strncpy(insertion+length, sql, strlen(sql));
    length+=strlen(sql);
    strncpy(insertion+length, before, strlen(before));
    length+=strlen(before);
    strncpy(insertion + length, ip, strlen(ip));
    length+=strlen(ip);
    strncpy(insertion+length, after, strlen(after));
    length+=strlen(after);
    strncpy(insertion+length, dest, strlen(dest));
    length+=strlen(dest);
    strncpy(insertion+length, after, strlen(after));
    length+=strlen(after);
    strncpy(insertion+length, classification, strlen(classification));
    length+=strlen(classification);
    strncpy(insertion+length, end, strlen(end));
    length+=strlen(end);
    insertion[length]='\0';
    */
    
    length = sprintf(insertion, "%s %s %s %s %s %s %s %s", sql, before, dest,
        after, ip, after, classification, end);
    );
    
    work W(C);
    W.exec(insertion);
    W.commit();
    
}