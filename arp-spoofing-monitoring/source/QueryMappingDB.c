#include "../header/QueryMappingDB.h"

int new_count = 0;
MYSQL *conn     = NULL;
MYSQL_RES *resp = NULL;
MYSQL_ROW row;
char sql_str[255];
char *sql_serv  = "localhost";
char *user      = "root";
char *passwd    = "unchi";
char *db_name   = "ip_mac_mapping";
char *tbl_name   = "map";
int ip_dup = 0;
int mac_dup = 0;



int queryMappingDB(char *ip_address, char *mac_address){
  memset( &sql_str[0] , 0x00 , sizeof(sql_str) );
  // mysql接続
  conn = mysql_init(NULL);
  if( !mysql_real_connect(conn,sql_serv,user,passwd,db_name,0,NULL,0) ){
    // error
    exit(-1);
  }
  //printf("m<%s, %s>\n", ip_address, mac_address);
  //DBに一致する<IP, MAC>があるか
  if(isMappedQuery(conn, resp, row, sql_str, sizeof(sql_str), tbl_name, 
              "ip_address", "mac_address", ip_address, mac_address)){
    //一致するエントリが存在
    ip_mac = IP_MAC_T;
  }else{
    //一致するエントリが存在しない
    ip_dup = countDup(conn, resp, row, sql_str, sizeof(sql_str), tbl_name, "ip_address", ip_address);
    mac_dup = countDup(conn, resp, row, sql_str, sizeof(sql_str), tbl_name, "mac_address", mac_address);    
    if(ip_dup > 0){
      //IPのみ一致する<IP, MAC>が存在
      ip_mac = IP_T;
    }else if(mac_dup > 0){
      //MACのみ一致する<IP, MAC>が存在
      ip_mac = MAC_T;
    }else{
      //全く新しいエントリ
      ip_mac = IP_MAC_F;
    }
  
  } 
  //後片づけ
  mysql_close(conn);
  return 0;
}

void setNewEntry(char *ip_address, char *mac_address){
  memset( &sql_str[0] , 0x00 , sizeof(sql_str) );
  // mysql接続
  conn = mysql_init(NULL);
  if( !mysql_real_connect(conn,sql_serv,user,passwd,db_name,0,NULL,0) ){
    // error
    exit(-1);
  }
  switch(ip_mac){
      case IP_T:
          sendDeleteQuery(conn, sql_str, sizeof(sql_str), tbl_name, "ip_address", ip_address);
          sendInsertQuery(conn, sql_str, sizeof(sql_str), tbl_name, ip_address, mac_address);    
          break;
      case MAC_T:
          sendDeleteQuery(conn, sql_str, sizeof(sql_str), tbl_name, "mac_address", mac_address);
          sendInsertQuery(conn, sql_str, sizeof(sql_str), tbl_name, ip_address, mac_address);    
          break;
      case IP_MAC_F:
          sendInsertQuery(conn, sql_str, sizeof(sql_str), tbl_name, ip_address, mac_address);    
          break; 
      default: break;

  }
  mysql_free_result(resp);
  mysql_close(conn);
  return;
}

void sendInsertQuery(MYSQL *conn, char* sql_str, int sizeof_sql, char *tbl_name, char *ip_address, char *mac_address){
  snprintf( &sql_str[0] , sizeof_sql-1 , "insert into %s values('%s' , '%s')",tbl_name, ip_address, mac_address);
  if( mysql_query( conn , &sql_str[0] ) ){
    // error
    printf("insert error : %s\n", sql_str);
    //mysql_close(conn);
    //exit(-1);
  }else{
    new_count++;
    printf("------------------[ %d ][new]------------------\n", new_count);
    printf("ip_address  : %s\n", ip_address);
    printf("mac_address : %s\n", mac_address);
    //printf("-----------------------------------------------\n");
  }
}

void sendSelectQuery(MYSQL *conn, MYSQL_RES *resp, MYSQL_ROW row, char* sql_str, int sizeof_sql, char *tbl_name){
  snprintf( &sql_str[0] , sizeof_sql-1 , "select * from %s", tbl_name);
  if( mysql_query( conn , &sql_str[0] ) ){
    // error
    //mysql_close(conn);
    //exit(-1);
  }else{
    resp = mysql_store_result(conn);
    while((row = mysql_fetch_row(resp)) != NULL ){
      printf( "| %s | %s |\n" , row[0] , row[1] );
    }
  }
}

void sendDeleteQuery(MYSQL *conn, char* sql_str, int sizeof_sql, char *tbl_name, char *key, char *value){
  snprintf( &sql_str[0] , sizeof_sql-1 , "delete from %s where %s = '%s'", tbl_name, key, value);
  if( mysql_query( conn , &sql_str[0] ) ){
    // error
       // printf("unchi\n");
    //mysql_close(conn);
    //exit(-1);
  }else{
    printf("------------------[ %d ][delete]------------------\n", new_count);
    printf("key  : %s\n", key);
    printf("value : %s\n", value);
  }
}

bool isMappedQuery(MYSQL *conn, MYSQL_RES *resp, MYSQL_ROW row, 
              char* sql_str, int sizeof_sql, char *tbl_name, 
              char *key1, char *key2, char *value1, char *value2){
  int count_mapped = 1;
  snprintf( &sql_str[0] , sizeof_sql-1 , "select count(*) from %s where %s = '%s' and %s = '%s'", tbl_name, key1, value1, key2, value2);
  if( mysql_query( conn , &sql_str[0] ) ){
    // error
       // printf("unchi\n");
    //mysql_close(conn);
    //exit(-1);
  }else{
    resp = mysql_store_result(conn);
    if((row = mysql_fetch_row(resp)) != NULL){
      count_mapped = atoi(row[0]);
    }
  }
  return (count_mapped > 0);
}

int countDup(MYSQL *conn, MYSQL_RES *resp, MYSQL_ROW row, char* sql_str, int sizeof_sql, char *tbl_name, char *key, char *value){
  snprintf( &sql_str[0] , sizeof_sql-1 , "select count(*) from %s where %s = '%s'", tbl_name, key, value);  
  if( mysql_query( conn , &sql_str[0] ) ){
    // error
    //mysql_close(conn);
    //exit(-1);
    return -1;

  }else{
    resp = mysql_store_result(conn);
    if((row = mysql_fetch_row(resp)) != NULL){
      return atoi(row[0]);
    }
  }
}

void getPairValue(char *pvalue, char *pkey, char *key, char *value){
  memset( &sql_str[0] , 0x00 , sizeof(sql_str) );
    // mysql接続
  conn = mysql_init(NULL);
  if( !mysql_real_connect(conn,sql_serv,user,passwd,db_name,0,NULL,0) ){
    // error
    exit(-1);
  }

  snprintf( &sql_str[0] , sizeof(sql_str)-1 , "select %s from %s where %s = '%s'",pkey, tbl_name, key, value);  
  if( mysql_query( conn , &sql_str[0] ) ){
    // error
    //mysql_close(conn);
    //exit(-1);
    //return;
  }else{
    resp = mysql_store_result(conn);
    if((row = mysql_fetch_row(resp)) != NULL){
    //printf("row[0] %s\n", row[0]);
    strcpy(pvalue, row[0]);
    }
  }
    //後片づけ
  mysql_free_result(resp);
  mysql_close(conn);
  return;
}

