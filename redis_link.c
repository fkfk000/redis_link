#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <hiredis/hiredis.h>

#include "postgres.h"
#include "funcapi.h"
#include "access/htup_details.h"
#include "access/reloptions.h"
#include "access/sysattr.h"
#include "catalog/indexing.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_foreign_table.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_user_mapping.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "commands/explain.h"
#include "foreign/fdwapi.h"
#include "foreign/foreign.h"
#include "miscadmin.h"
#include "nodes/bitmapset.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/pg_list.h"
#include "optimizer/cost.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "optimizer/restrictinfo.h"

#if PG_VERSION_NUM < 120000
#include "optimizer/var.h"
#else
#include "access/table.h"
#include "optimizer/optimizer.h"
#endif

#include "parser/parse_relation.h"
#include "parser/parsetree.h"
#include "utils/builtins.h"
#include "utils/elog.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"

// Here are things needed for declaration
Datum redis_link_handler(PG_FUNCTION_ARGS);
Datum redis_link_validator(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(redis_link_handler);
PG_FUNCTION_INFO_V1(redis_link_validator);
PG_MODULE_MAGIC;

// For fdw_private
typedef struct redisCtx
{
    // Infromation for connection.
    char *host;
    char *password;
    int *port;

    // Infromation for foreign server and table.
    ForeignServer *foreign_server;
    ForeignTable *foreign_table;

    // redis related object.
    redisContext *connection_context;
    //redisReply *reply;

    // Infromation for operation type
    CmdType cmd_type;

    // section for select
    char *where_claus; // only be useful to key.

    // General ifromation for the foreign table
    double rows;
} redisCtx;

// Helper function declaration
static bool redis_is_valid_option(const char *option_name, Oid option_typpe);
void set_redis_ctx(Oid foreigntableid, redisCtx *redis_ctx);
void set_where_claus(RelOptInfo *baserel, redisCtx *redis_ctx, List *baserestrictinfo);



// Declaration of functions
void redisLinkGetForeignRelSize(PlannerInfo *root,
                                RelOptInfo *baserel, Oid foreigntableid);



// Declaration of macros
#define OPT_KEY "key"
#define OPT_VALUE "value"
#define OPT_TTL "ttl"
#define OPT_COLUMN "column"

// Declaration of various structs

// used in valid process of settings
typedef struct redis_various_option
{
    char *option_name;
    Oid option_type;
} redis_various_option;

static redis_various_option redis_avaliable_options[] = {
    {OPT_KEY, ForeignTableRelidIndexId},
    {OPT_VALUE, ForeignTableRelidIndexId},
    {OPT_TTL, ForeignTableRelidIndexId},
    {OPT_COLUMN, AttributeRelationId},
    // This is for iteration
    {NULL, InvalidOid}};

// We just iter through the redis_various_option to see whether the option and option type exist
// in predefined tables.
static bool redis_is_valid_option(const char *option_name, Oid option_typpe)
{
    redis_various_option *option;
    for (option = redis_avaliable_options; option->option_name != NULL; option++)
    {
        if (strcmp(option->option_name, option_name) == 0 && option_typpe == option->option_type)
        {
            return true;
        }
    }
    return false;
}

Datum redis_link_validator(PG_FUNCTION_ARGS)
{
    //  we now start to do somethig.
    List *options = untransformRelOptions(PG_GETARG_DATUM(0));
    Oid option_type = PG_GETARG_OID(1);
    ListCell *lc;
    foreach (lc, options)
    {
        DefElem *def = (DefElem *)lfirst(lc);
        if (!redis_is_valid_option(def->defname, option_type))
        {
            elog(ERROR, "not support this. The name is %s and the option is %s", def->defname, option_type);
        }
    }
    PG_RETURN_VOID();
}

/* Internal function implement





*/

// This function will set the proper values for redis_ctx and try to connect to redis.
void set_redis_ctx(Oid foreigntableid, redisCtx *redis_ctx)
{
    elog(INFO, "*** %s", __FUNCTION__);
    redis_ctx->foreign_table = GetForeignTable(foreigntableid);
    redis_ctx->foreign_server = GetForeignServer(redis_ctx->foreign_table->serverid);
    List *options = redis_ctx->foreign_server->options;
    ListCell *lc;
    redis_ctx->port = 6379;
    foreach (lc, options)
    {
        DefElem *def = (DefElem *)lfirst(lc);
        if (strcmp(def->defname, "host") == 0)
        {
            redis_ctx->host = defGetString(def);
        }
        else if (strcmp(def->defname, "password") == 0)
        {
            redis_ctx->password = defGetString(def);
        }
        else if (strcmp(def->defname, "port") == 0)
        {
            redis_ctx->port = defGetInt32(def);
        }
        else
        {
            elog(ERROR, "run into unknow database configuration. def is %s", def->defname);
        }
    }
    if(redis_ctx->host == NULL)
    {
        int len_locahost = strlen("localhost");
        redis_ctx->host = palloc(len_locahost+1);
        memcpy(redis_ctx->host, "localhost", len_locahost);
        redis_ctx->host[len_locahost] = '\0';
    }
    redis_ctx->connection_context = redisConnect(redis_ctx->host, redis_ctx->port);
    if(redis_ctx->connection_context == NULL)
    {
        elog(ERROR, "Could not connect to redis server");
    }
}




// This function is to parse where claus for keys in select statements.
// for value or ttl, we don't do this because in this situation, we need to retrive all the tuples.
void set_where_claus(RelOptInfo *baserel, redisCtx *redis_ctx, List *baserestrictinfo)
{

}

/* Here is the main part of the programme







*/


// Base for any other function and get realtion size
void redisLinkGetForeignRelSize(PlannerInfo *root,
                                RelOptInfo *baserel, Oid foreigntableid)
{
    elog(INFO, "*** %s", __FUNCTION__);
    redisCtx *redis_ctx = (redisCtx *)palloc(sizeof(redisCtx));
    baserel->fdw_private = redis_ctx;
    set_redis_ctx(foreigntableid, redis_ctx);
    redisReply *redis_reply = redisCommand(redis_ctx->connection_context, "dbsize");
    if (redis_reply == NULL)
    {
        // seems not going to happen, but just in case
        elog(ERROR, "could not execute dbsize");
    }
    double size = (double)redis_reply->integer;
    baserel->rows = size;
    baserel->tuples = size;
    if (root->parse->commandType == CMD_SELECT)
    {

    }
    else
    {
        elog(ERROR, "Sorry, we don't support command beyond select right now");
    }
    
}




Datum redis_link_handler(PG_FUNCTION_ARGS)
{
    FdwRoutine *froutine = makeNode(FdwRoutine);
    froutine->GetForeignRelSize = redisLinkGetForeignRelSize;
    /*froutine->GetForeignPaths = redisTestGetForeignPaths;
    froutine->GetForeignPlan = redisTestGetForeignPlan;
    froutine->BeginForeignScan = redisTestBeginForeignScan;
    froutine->IterateForeignScan = redisTestIterateForeignScan;
    froutine->ReScanForeignScan = redisTestReScanForeignScan;
    froutine->EndForeignScan = redisTestEndForeignScan; 
    */
    PG_RETURN_POINTER(froutine);
}