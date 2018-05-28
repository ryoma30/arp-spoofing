#ifndef _Query_Mapping_DB_H_
#define _Query_Mapping_DB_H_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <mysql/mysql.h>

#include "SendTrapIcmp.h"

bool is_invalid;

//DB内にそれぞれが存在するか否か
typedef enum IP_MAC_DUP{
    IP_MAC_T,           //どちらも存在
    IP_T,               //MACのみ存在
    MAC_T,              //MACのみ存在
    IP_MAC_F            //どちらも存在しない
}IP_MAC;

IP_MAC ip_mac;

bool ip_flag, mac_flag;

int queryMappingDB(char *, char *);
void setNewEntry(char *, char *);
void sendInsertQuery(MYSQL *, char *, int, char *, char *, char *);
void sendSelectQuery(MYSQL *, MYSQL_RES *, MYSQL_ROW, char *, int, char *);
void sendDeleteQuery(MYSQL *, char *, int, char *, char *, char *);
bool isMappedQuery(MYSQL *, MYSQL_RES *, MYSQL_ROW, char *, int, char *, char *, char *, char *, char *);
int countDup(MYSQL *, MYSQL_RES *, MYSQL_ROW, char *, int, char *, char *, char *);
void getPairValue(char *, char *, char *, char *);
#endif //_Query_Mapping_DB_H_