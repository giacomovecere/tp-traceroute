#include <iostream>
#include <cstdlib>
#include <pqxx/pqxx>
#include <string>
#define MAX_VALUE 500

using namespace std;
using namespace pqxx;

class database{
    connection* c;
public:
    database();
    ~database();
    void insertion(char*, char*);
}