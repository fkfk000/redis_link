

#ifndef FDW_REDIS_H
#define FDW_REDIS_H

#include <hiredis/hiredis.h>
// #include "funcapi.h"
#include "access/hash.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_foreign_table.h"
#include "foreign/foreign.h"
#include "nodes/pathnodes.h"
#include "nodes/execnodes.h"
#include "catalog/pg_type.h"
#include "nodes/parsenodes.h"
#include "parser/parsetree.h"



#define FDW_SERVER_PORT_LEN 128 // 128 seems a good guess of len for something like 127.0.0.1:9002
#define FDW_NUM_SERVER 16       // basically, 16 should be enough for normal size of redids cluster.

typedef struct fdw_redisServer
{
    char host_port[FDW_SERVER_PORT_LEN]; // something like 127.0.0.1:9002
    redisContext *c;
    int numCommand;
} fdw_redisServer;

typedef struct fdw_command
{
    char *command;
    struct fdw_command *next;
} fdw_command;

typedef enum fdw_tableType
{
    FDW_TYPE_STRING,
    FDW_TYPE_HASH,
    FDW_TYPE_SET,
    FDW_TYPE_INVALID,
} fdw_tableType;

typedef enum fdw_ttlType
{
    FDW_TTL_TYPE_SECOND,
    FDW_TTL_TYPE_MILLISECOND,
} fdw_ttlType;

typedef struct fdw_redisScanState
{
    fdw_tableType type;
    List *connection_list;
    ListCell *current_cell;
    int next_pos; // pos for the number in the retrun value of redis.
    int current_pos;       // the cur that needs to be used in the next run.
    // -1 means we haven't started scan, and 0 means that this is the last run.

    // the prefix for the table.
    // if the table type is not string, this will store the key name for that table.
    char *prefix;            // 
    redisReply *r; // this is used for store the list of each sscan command.
    // the relative pos for each type.
    // as the key can be happen at the second column and val happen at the third column.
    AttrNumber key_pos;
    AttrNumber val_pos;
    AttrNumber ttl_pos;
    // we need to support second and millisecond ttl.
    fdw_ttlType ttl_type;
    // a scan part should look like "scan 12 match *key* "
    // this sould store match *key*
    StringInfo match_part;
    StringInfo scan_command;

    // below function is tuple callback function.
    // for scan, we use a common read flow to redis server and
    // use these callback functions to provide type specific commnands for each redis key type.
    char **(*returnTuple)(struct fdw_redisScanState *status);
    char *(*scanCommand)(struct fdw_redisScanState *status);

} fdw_redisScanState;

typedef struct fdw_redisRelationInfo
{
    CmdType cmd_type;
    char *where_clause;
    char *prefix_name;

} fdw_redisRelationInfo;

// current we only support these.
enum REDIS_WHERE_OP
{
    OPERATION_INVALID = -1,
    OPERATION_LIKE, // ~~ in op name
    OPERATION_EQUAL // = in op name
};

fdw_redisServer *getOneConnection(Oid foreigntableid);

// we will retrun a connection from host_port like 127.0.0.1:9001
fdw_redisServer *fdw_make_fdw_redisServer(char *host_port);

// this function process host and port like "  127.0.0.1:9001    "
// into "127.0.0.1:9001"
char *process_host_port(char *host_port);

char *fdw_strdup(char *s);

// this function is used to set the host and port
// for hosts like "127.0.0.1:9001".
// the address must the same format. i.e. no space before or after the address.
void set_host_port(char *host_port, char **host, int *port);

// this function set the scan type and the prefix of a scan state. If there is a prefix.
void set_scan_type_prefix(fdw_redisScanState *state, ForeignTable *table);

// this furnction will set the positions for key/val/ttl.
// users should be able to use the first column as val and third column as ttl.
// and all the column should be able to have the their own name.
void set_scan_position(fdw_redisScanState *state, ForeignTable *table);

// we need to parse the where conditions, if users use select * from tb where key like 'key%1%2'
// this needs to be transformed into match key*1*2
// and sent to redis
void set_where_clause(ForeignScanState *node, fdw_redisScanState *scan_state);

// used in set_where_clause to transform the where condition into redis match.
void parse_where(fdw_redisRelationInfo *redis_info, Expr *expr);

// used in parse_where
// this function will set the operation oid
void get_operation_infromation(OpExpr *expr, Oid *left_oid, Oid *right_oid, Oid *operation_type);

int get_operation_type(char *name); // to identify = in where a = 1;

// this is used to check if the variable column is key colum or not.
// as we support different various column order.
bool check_is_key_column(char *name, Oid foreigntableid);

// this fucntion will convet the connections to redis server stored in fdw_connection_hash
// so the connections can be used in subsequent read opeartions.
List *make_connection_list(HTAB *connection_hash);

// let's set the command that actually used in select command here:
// different table type will have different command;
void set_scan_command(fdw_redisScanState *scan_state, int current_pos);

// this function is used to check if the scan is end
// and we can end the whole iteration.
bool scan_is_done(fdw_redisScanState *state);

// this function will check if we need to execute scan cur match pattern again
// from redis server.
bool scan_need_retrieve_data(fdw_redisScanState *state);

// in this function, we will execute sacn command and move connection_list if necessary.
// return true is we successfully executed scan command (and its friends)
// return false if we have reached to the end. we will mark current cell as NIL.
// So in next run, we will complete the scan.
bool scan_retrieve_data(fdw_redisScanState *state);

/*

In a normal scan run, we need first to use scan_retrieve_data to get the data like:

127.0.0.1:6379> scan 0 match key*
1) "24"
2)  1) "key7"
    2) "key97"
    3) "key89"
    4) "key88"
    5) "key85"
    6) "key92"
    7) "key18"
    8) "key98"
    9) "key33"
   10) "key87"
   11) "key14"


Then, we need to use scan_append_commandAndsend to append the get key7/...... via async command.

Later, we will use command to read the command to get the result in a saparate memory context.
*/
void scan_append_command(fdw_redisScanState *state);

/*
This function will return the data for next row. retrun false if there is no data can be found.

*/
bool scan_get_next_data(fdw_redisScanState *state, char **key, char **val, long long *ttl);

/*

in the scan, we need to iterate through cursers: like:

127.0.0.1:6379> scan 0 match key*
1) "24"
2)  1) "key7"
    2) "key97"
    3) "key89"
    4) "key88"
    5) "key85"
    6) "key92"
    7) "key18"
    8) "key98"
    9) "key33"
   10) "key87"
   11) "key14"

so we need to form the comand scan 24 match key* to redis server to get the next value.

*/
StringInfo scan_command_withPos(fdw_redisScanState *state, int pos);





// return true if the reply from redis command is a MOVED commnad.
// false if it is not or the reply is NULL.
bool replyWithMOVED(redisReply *r);

// this is the retrun function for string type table.
// the position should be the same as the table definition.
char **stringReturnTuple(struct fdw_redisScanState *status);

// this is the function for forming the scan command of string table type.
char *stringScanCommand(struct fdw_redisScanState *status);

// generic read flow for scan.
// different table type should have different callback function.
char **fdw_redisReadFlow(struct fdw_redisScanState *flow);


// this is the retrun function for hash type table.
// the position should be the same as the table definition.
char **hashReturnTuple(struct fdw_redisScanState *status);

// this is the function for forming the scan command of hash table type.
char *hashScanCommand(struct fdw_redisScanState *status);



// this is the retrun function for set type table.
// the position should be the same as the table definition.
// currently for set data type, there must be a colum with key, which is the prefix name.
// TODO: remove this constrain.
char **setReturnTuple(struct fdw_redisScanState *status);

// this is the function for forming the scan command of set table type.
char *setScanCommand(struct fdw_redisScanState *status);


typedef struct fdw_redisInsertState
{
    int tableType; // we need to know if this is a sting table/hash/......
    // for connections, we use the global varable connection_hash;
    char *prefix; // the prefix of this table. This will be used in table check.
    List *commandQueue1;
    List *commandQueue2;
    // we have multiple columns. each column has its own typinput and typoutput
    regproc *typinput;
    regproc *typoutput;
    // the relative pos for each type.
    // as the key can be happen at the second column and val happen at the third column.
    AttrNumber key_pos;
    AttrNumber val_pos;
    AttrNumber ttl_pos;
    Oid foreigntableid;
    // we use this callback function to generate the actual redis set command.
    // in many scenarios, we might need to return more than 1 command. Like one command to set the key and val,
    // a second command set the expire time.
    // the end of the char ** should point to NULL. So we could end properly.
    char **(*fdw_insertCommand)(struct fdw_redisInsertState *flow, char *key, char* val, char *ttl);
    MemoryContext insertContext;
    redisContext *c; // this is the first C that we use when inserting into the fist queue.
} fdw_redisInsertState;


// this function will set the typinput and typoutput from the column. 
// typoutput will be used when getting the string from slot. 
void fdw_redisInsert_setTyp(fdw_redisInsertState *flow, Oid foreigntableid);

// this function will set the key_pos/val_pos/ttl_pos, as we allow them appear in different order.
// we will alos set table type here.
void fdw_redisInsert_setPos(fdw_redisInsertState *flow, Oid foreigntableid);

// this function will set the prefix of the table.
// the prefix will be used in 
void fdw_redisInsert_setPrefix(fdw_redisInsertState *flow, Oid foreigntableid);


// for each kind of insert, we will need different 
char **string_fdw_insertCommand(fdw_redisInsertState *flow, char *key, char* val, char *ttl);

char **hash_fdw_insertCommand(fdw_redisInsertState *flow, char *key, char *val, char *ttl);

// this is the command in insert command.
// we append a redis context in each command, so we can spot the errors and correct them to the right context.
typedef struct fdw_insertCommandC
{
    char *command;
    redisContext *c;
}fdw_insertCommandC;


// generic insert flow for insert.
// different table type should have different callback function.
// this will be called at the end of the insert command, so multiple commands could be pipelined.
void fdw_redisInsertFlow(struct fdw_redisInsertState *flow);


// this function will extract the host:port from error message.
bool hostIP(redisReply *r, char **hostIP);

#endif