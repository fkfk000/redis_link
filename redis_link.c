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

/* For fdw_private





*/

#define MAX_CACHED_MEMORY 8 * 1024 * 1024 // 8MB

// For now, we actually only support string.
enum REDIS_TABLE_TYPE
{
    REDIS_TABLE_INVALID = -1,
    REDIS_TABLE_STRING,
    REDIS_TABLE_HSET
};

typedef struct redisColumn
{
    char *column_name;
    int attnum;
    Oid atttypid;
    Oid atttypmod;
    regproc typoutput; // type output conversion function
    regproc typinput;  // type input conversion function
} redisColumn;

typedef struct redisTableInfo
{
    char *tablename;
    int column_num;
    redisColumn *columns;
} redisTableInfo;

typedef struct redisCtx
{
    // Infromation for connection.
    char *host;
    char *password;
    int port;

    // Infromation for foreign server and table.
    ForeignServer *foreign_server;
    ForeignTable *foreign_table;
    int table_type;
    char *prefix_name;
    redisTableInfo *table_info;

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

typedef struct redisScanState
{
    redisCtx *redis_ctx;
    redisReply *redis_reply; // used for retrive all the keys.
    redisReply *iter_reply;  // used for iter in redisGetReply.
    char *search_name;
    int current_cursor; // scan cursor
    int list_capacity;
    int list_current;
    char **keys;                 // store all the keys returned from one scan operation.
    MemoryContext upper_context; // beacuse in iter scan, memory would be cleared. we need this to save some infromation.

} redisScanState;

typedef struct redisInsertState
{
    redisCtx *redis_ctx;
    int current_buffered_data; // how much data is cached.
    int cached_cmd;            // how many redisAppendCommand is memory.
    redisReply *iter_reply;    // used for consume the retruned value from redisAppendCommand.
    AttInMetadata *attmeta;    // description of the tuple.
    MemoryContext tmp_context; // used in each iter of insert.

    // used for sotore values from slot.
    // we used use them in tmp context, keep them shot-lived.
    char *key;
    char *value;
    char *ttl;
} redisInsertState;

// current we only support these.
enum REDIS_WHERE_OP
{
    OPERATION_INVALID = -1,
    OPERATION_LIKE, // ~~ in op name
    OPERATION_EQUAL // = in op name
};

// Helper function declaration
static bool redis_is_valid_option(const char *option_name, Oid option_typpe);
void set_redis_ctx(Oid foreigntableid, redisCtx *redis_ctx);
void set_redis_table_column(Oid foreigntableid, redisCtx *redis_ctx);
void set_type_inout_function(Oid typeid, regproc *typinput, regproc *typoutput);
void set_where_clause(RelOptInfo *baserel, redisCtx *redis_ctx, List *baserestrictinfo);
bool is_valid_key_type(Oid key_type);
void get_operation_infromation(OpExpr *expr, Oid *left_oid, Oid *rght_oid, Oid *operation_type);
void parse_where(redisCtx *redis_ctx, Expr *expr);
int get_operation_type(char *name); // to identify = in where a = 1;
char *make_tablename_into_where_clause(redisCtx *redis_ctx);

// Declaration of functions
void redisLinkGetForeignRelSize(PlannerInfo *root,
                                RelOptInfo *baserel, Oid foreigntableid);

void redisLinkGetForeignPaths(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid);

ForeignScan *redisLinkGetForeignPlan(PlannerInfo *root, RelOptInfo *baserel,
                                     Oid foreigntableid, ForeignPath *best_path,
                                     List *tlist, List *scan_clauses, Plan *outer_plan);

void redisLinkBeginForeignScan(ForeignScanState *node, int eflags);
static TupleTableSlot *redisLinkIterateForeignScan(ForeignScanState *node);
static void redisLinkReScanForeignScan(ForeignScanState *node);
static void redisLinkEndForeignScan(ForeignScanState *node);
static List *redisLinkPlanForeignModify(PlannerInfo *root, ModifyTable *plan,
                                        Index resultRelation,
                                        int subplan_index);
static TupleTableSlot *redisLinkExecForeignInsert(EState *estate,
                                                  ResultRelInfo *rinfo,
                                                  TupleTableSlot *slot,
                                                  TupleTableSlot *planSlot);

static void redisLinkBeginForeignModify(ModifyTableState *mtstate,
                                        ResultRelInfo *rinfo,
                                        List *fdw_private,
                                        int subplan_index,
                                        int eflags);
static void redisLinkEndForeignModify(EState *estate,
                                      ResultRelInfo *rinfo);

static void redisLinkBeginForeignInsert(ModifyTableState *mtstate,
                                        ResultRelInfo *rinfo);

static void redisLinkEndForeignInsert(EState *estate,
                                      ResultRelInfo *rinfo);

// Declaration of macros
#define OPT_KEY "key"
#define OPT_VALUE "value"
#define OPT_TTL "ttl"
#define OPT_COLUMN "column"
#define OPT_TABLE_TYPE "tabletype"
#define OPT_PREFIX_NAME "prefixname"
#define OPT_HOST "host"

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
    {OPT_PREFIX_NAME, ForeignTableRelationId},
    {OPT_TTL, ForeignTableRelidIndexId},
    {OPT_COLUMN, AttributeRelationId},
    {OPT_TABLE_TYPE, ForeignTableRelationId},
    {OPT_HOST, ForeignTableRelationId},
    // This is for iteration
    {NULL, InvalidOid}};

// We just iter through the redis_various_option to see whether the option and option type exist
// in predefined tables.
static bool redis_is_valid_option(const char *option_name, Oid option_typpe)
{
    //elog(INFO, "*** %s", __FUNCTION__);
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
    //elog(INFO, "*** %s", __FUNCTION__);
    //  we now start to do somethig.
    List *options = untransformRelOptions(PG_GETARG_DATUM(0));
    Oid option_type = PG_GETARG_OID(1);
    ListCell *lc;
    foreach (lc, options)
    {
        DefElem *def = (DefElem *)lfirst(lc);
        if (!redis_is_valid_option(def->defname, option_type))
        {
            elog(ERROR, "not support this. The name is %s and the option is %u", def->defname, option_type);
        }
    }
    PG_RETURN_VOID();
}

/* Internal function implement





*/

bool is_valid_key_type(Oid key_type)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    if (key_type == TEXTOID || key_type == CHAROID || key_type == BPCHAROID || key_type == VARCHAROID)
    {
        return true;
    }
    return false;
}

int get_operation_type(char *name)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    if (strcmp(name, "~~") == 0)
    {
        return OPERATION_LIKE;
    }
    else if (strcmp(name, "=") == 0)
    {
        return OPERATION_EQUAL;
    }
    else
    {
        return OPERATION_INVALID;
    }
}

/*
    Because the real key in redis would be like tablename+key:value.
    So, when we need to lookup for some data, we shou do this by 
    lookup the key in tablename+whereclause.
    the char * is palloced. 
*/
char *make_tablename_into_where_clause(redisCtx *redis_ctx)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    int name_len = strlen(redis_ctx->prefix_name) + strlen(redis_ctx->where_claus);
    char *full_name = (char *)palloc0(name_len + 1);
    strcpy(full_name, redis_ctx->prefix_name);
    strcat(full_name, redis_ctx->where_claus);
    full_name[name_len] = '\0';
    // previous where_claus is palloced, so it shoule be fine.
    return full_name;
}

void get_operation_infromation(OpExpr *expr, Oid *left_oid, Oid *right_oid, Oid *operation_type)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    HeapTuple tuple;
    Form_pg_operator form;
    char *op_name;
    *left_oid = InvalidOid;
    *right_oid = InvalidOid;
    tuple = SearchSysCache1(OPEROID, ObjectIdGetDatum(expr->opno));
    if (!HeapTupleIsValid(tuple))
    {
        elog(ERROR, "ERROR when look up for system cache for get_left_type");
    }
    form = (Form_pg_operator)GETSTRUCT(tuple);
    *left_oid = form->oprleft;
    *right_oid = form->oprright;
    op_name = NameStr(form->oprname);
    *operation_type = get_operation_type(op_name);
    ReleaseSysCache(tuple);
    if (*left_oid == InvalidOid || *right_oid == InvalidOid || *operation_type == OPERATION_INVALID)
    {
        elog(ERROR, "ERROR during getting the oid of both side of operand, or failed to get operation name");
    }
}

// This function will set the proper values for redis_ctx and try to connect to redis.
void set_redis_ctx(Oid foreigntableid, redisCtx *redis_ctx)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    redis_ctx->foreign_table = GetForeignTable(foreigntableid);
    redis_ctx->foreign_server = GetForeignServer(redis_ctx->foreign_table->serverid);
    redis_ctx->table_type = REDIS_TABLE_INVALID;
    redis_ctx->host = NULL;
    redis_ctx->table_info = (redisTableInfo *)palloc(sizeof(redisTableInfo));
    List *options = redis_ctx->foreign_table->options;
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
        else if (strcmp(def->defname, "tabletype") == 0)
        {
            char *table_type = defGetString(def);
            if (strcmp(table_type, "string") == 0)
            {
                redis_ctx->table_type = REDIS_TABLE_STRING;
            }
            else if (strcmp(table_type, "hset") == 0)
            {
                redis_ctx->table_type = REDIS_TABLE_HSET;
            }
            else
            {
                redis_ctx->table_type = REDIS_TABLE_INVALID;
            }
        }
        else if (strcmp(def->defname, "prefixname") == 0)
        {
            redis_ctx->prefix_name = defGetString(def);
        }
        else
        {
            elog(ERROR, "run into unknow database configuration. def is %s", def->defname);
        }
    }
    if (redis_ctx->host == NULL)
    {
        int len_locahost = strlen("localhost");
        redis_ctx->host = palloc(len_locahost + 1);
        memcpy(redis_ctx->host, "localhost", len_locahost);
        redis_ctx->host[len_locahost] = '\0';
    }
    if (redis_ctx->table_type == REDIS_TABLE_INVALID)
    {
        elog(ERROR, "Unknown table type");
    }
    redis_ctx->connection_context = redisConnect(redis_ctx->host, redis_ctx->port);
    if (redis_ctx->connection_context == NULL)
    {
        elog(ERROR, "Could not connect to redis server");
    }
    set_redis_table_column(foreigntableid, redis_ctx);
}

// For now, we just record all the
void set_redis_table_column(Oid foreigntableid, redisCtx *redis_ctx)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    Relation rel;
    TupleDesc tupledesc;
    redisTableInfo *table_info = redis_ctx->table_info;
    table_info->tablename = get_rel_name(foreigntableid);
    rel = heap_open(foreigntableid, NoLock);
    tupledesc = rel->rd_att;
    table_info->column_num = tupledesc->natts;
    table_info->columns = (redisColumn *)palloc(table_info->column_num * sizeof(redisColumn));
    for (int i = 0; i < table_info->column_num; i++)
    {
        Form_pg_attribute att = &tupledesc->attrs[i];
        table_info->columns[i].column_name = pstrdup(NameStr(att->attname));
        table_info->columns[i].atttypid = att->atttypid;
        table_info->columns[i].atttypmod = att->atttypmod;
        set_type_inout_function(table_info->columns[i].atttypid, &table_info->columns[i].typinput, &table_info->columns[i].typoutput);
    }
    heap_close(rel, NoLock);
}

void set_type_inout_function(Oid typeid, regproc *typinput, regproc *typoutput)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    HeapTuple tuple;
    tuple = SearchSysCache1(TYPEOID, ObjectIdGetDatum(typeid));
    if (!HeapTupleIsValid(tuple))
    {
        elog(ERROR, "ERROR when open the catalog for inout function");
    }
    Form_pg_type pg_type = (Form_pg_type)GETSTRUCT(tuple);
    *typinput = pg_type->typinput;
    *typoutput = pg_type->typoutput;
    ReleaseSysCache(tuple);
}

// parse_where
//
void parse_where(redisCtx *redis_ctx, Expr *expr)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    Oid left_oid;
    Oid right_oid;
    Oid operation_type;
    Const *left_const;
    OpExpr *opexpr;
    switch (nodeTag(expr))
    {
    case T_OpExpr:
        get_operation_infromation((OpExpr *)expr, &left_oid, &right_oid, &operation_type);
        if (operation_type == OPERATION_LIKE)
        {
            opexpr = (OpExpr *)expr;
            left_const = lsecond(opexpr->args);
            char *arg = TextDatumGetCString(left_const->constvalue);
            redis_ctx->where_claus = pstrdup(arg);
            for (int i = 0; i < strlen(redis_ctx->where_claus); i++)
            {
                if (redis_ctx->where_claus[i] == '%')
                {
                    redis_ctx->where_claus[i] = '*';
                }
            }
        }
        else
        {
            elog(ERROR, "sorry, we only support like operation at this stage.");
        }

        break;

    default:
        break;
    }
}

// This function is to parse where claus for keys in select statements.
// for value or ttl, we don't do this because in this situation, we need to retrive all the tuples.
void set_where_clause(RelOptInfo *baserel, redisCtx *redis_ctx, List *baserestrictinfo)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    Expr *expr;
    RestrictInfo *rinfo;
    ListCell *lc;
    if (baserestrictinfo == NULL)
    {
        redis_ctx->where_claus = NULL;
        return;
    }
    if (list_length(baserestrictinfo) == 1)
    {
        // we only need to run once.
        foreach (lc, baserestrictinfo)
        {
            rinfo = (RestrictInfo *)lfirst(lc);
            expr = rinfo->clause;
            parse_where(redis_ctx, expr);
        }
    }
    else
    {
        elog(ERROR, "sorry, currently we only support one where clues");
    }
}

/* Here is the main part of the programme







*/

// Base for any other function and get realtion size
// in this function, we also set for the table name.
void redisLinkGetForeignRelSize(PlannerInfo *root,
                                RelOptInfo *baserel, Oid foreigntableid)
{
    //elog(INFO, "*** %s", __FUNCTION__);
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
        set_where_clause(baserel, redis_ctx, baserel->baserestrictinfo);
    }
    else
    {
        elog(ERROR, "Sorry, we don't support command beyond select right now");
    }
}

void redisLinkGetForeignPaths(PlannerInfo *root, RelOptInfo *baserel, Oid foreigntableid)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    Cost startup_cost;
    Cost total_cost;
    redisCtx *redis_ctx = (redisCtx *)baserel->fdw_private;
    startup_cost = 25; // randomly picked up.
    if (redis_ctx->cmd_type == CMD_SELECT)
    {
        total_cost = startup_cost + baserel->rows;
    }
    else
    {
        total_cost = 1500; // temp setting.
    }
    Path *path = (Path *)create_foreignscan_path(root, baserel, NULL, baserel->rows, startup_cost, total_cost, NIL, NULL, NULL, NIL);
    add_path(baserel, path);
}

ForeignScan *redisLinkGetForeignPlan(PlannerInfo *root, RelOptInfo *baserel,
                                     Oid foreigntableid, ForeignPath *best_path,
                                     List *tlist, List *scan_clauses, Plan *outer_plan)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    scan_clauses = extract_actual_clauses(scan_clauses, false);
    redisCtx *redis_ctx = baserel->fdw_private;
    return make_foreignscan(tlist, scan_clauses, baserel->relid, NIL, (List *)redis_ctx, NIL, NIL, NULL);
}

void redisLinkBeginForeignScan(ForeignScanState *node, int eflags)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    redisScanState *redis_scan_state = (redisScanState *)palloc0(sizeof(redisScanState));
    ForeignScan *plan = (ForeignScan *)node->ss.ps.plan;
    redis_scan_state->redis_ctx = (redisCtx *)plan->fdw_private;
    redisCtx *redis_ctx = redis_scan_state->redis_ctx;
    char *search_name; // tablename+key condition. like tablename:*
    // This means that we are going to retrive all the keys under that table.
    if (redis_scan_state->redis_ctx->where_claus == NULL)
    {
        char *where_clause = (char *)palloc0(2);
        where_clause[0] = '*';
        where_clause[1] = '\0';
        redis_ctx->where_claus = where_clause;
    }
    search_name = make_tablename_into_where_clause(redis_ctx);
    redis_scan_state->search_name = search_name;
    redis_scan_state->redis_reply = redisCommand(redis_ctx->connection_context, "scan 0 match %s", redis_scan_state->search_name);
    if (redis_scan_state->redis_reply == NULL)
    {
        elog(ERROR, "failed in begin scan. we could not get reply from redis");
    }
    redis_scan_state->current_cursor = atoi(redis_scan_state->redis_reply->element[0]->str);
    redis_scan_state->list_capacity = (int)redis_scan_state->redis_reply->element[1]->elements;
    redis_scan_state->list_current = 0;
    redis_scan_state->upper_context = CurrentMemoryContext;
    node->fdw_state = (void *)redis_scan_state;
}

TupleTableSlot *redisLinkIterateForeignScan(ForeignScanState *node)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    MemoryContext old_context;
    HeapTuple tuple;
    TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
    AttInMetadata *att;
    char **keys; // we need first extract all the keys from a single scan operation.
    char *value;
    int ttl;
    int i;
    int list_capacity; //denote the returned length of list from a single scan.
    int iter_redis_reply_status;
    char **slot_build_strings;
    char *buffer_ltoa;
    att = TupleDescGetAttInMetadata(node->ss.ss_currentRelation->rd_att);
    redisScanState *redis_scan_state = (redisScanState *)node->fdw_state;
    ExecClearTuple(slot);
    if (redis_scan_state->current_cursor == 0 && redis_scan_state->list_current == redis_scan_state->list_capacity)
    {
        return slot;
    }
    while (redis_scan_state->current_cursor != 0 && redis_scan_state->list_current == 0 && redis_scan_state->list_capacity == 0)
    {
        freeReplyObject(redis_scan_state->redis_reply);
        redis_scan_state->redis_reply = redisCommand(redis_scan_state->redis_ctx->connection_context, "scan %d match %s", redis_scan_state->current_cursor, redis_scan_state->search_name);
        if (redis_scan_state->redis_reply == NULL)
        {
            elog(ERROR, "failed in begin scan. we could not get reply from redis");
        }
        redis_scan_state->current_cursor = atoi(redis_scan_state->redis_reply->element[0]->str);
        redis_scan_state->list_capacity = (int)redis_scan_state->redis_reply->element[1]->elements;
        redis_scan_state->list_current = 0;
    }
    if (redis_scan_state->current_cursor == 0 && redis_scan_state->list_current == redis_scan_state->list_capacity)
    {
        return slot;
    }
    keys = redis_scan_state->keys;
    // for now, we only support key value ttl in table column.
    // so the magic number 3 is for 3 supported columns.
    if (redis_scan_state->list_current == 0)
    {
        old_context = MemoryContextSwitchTo(redis_scan_state->upper_context);
        if (keys != NULL)
        {
            // it seems that pfree is quite efficient
            // and has less over then free from std.
            pfree(keys);
        }
        keys = (char **)palloc(sizeof(char **) * redis_scan_state->list_capacity);
        list_capacity = redis_scan_state->list_capacity;
        for (i = 0; i < list_capacity; i++)
        {
            keys[i] = redis_scan_state->redis_reply->element[1]->element[i]->str;
            redisAppendCommand(redis_scan_state->redis_ctx->connection_context, "get %s", keys[i]);
            redisAppendCommand(redis_scan_state->redis_ctx->connection_context, "ttl %s", keys[i]);
        }
        redis_scan_state->keys = keys;
        MemoryContextSwitchTo(old_context);
    }
    iter_redis_reply_status = redisGetReply(redis_scan_state->redis_ctx->connection_context, (void **)&redis_scan_state->iter_reply);
    if (iter_redis_reply_status == REDIS_ERR)
    {
        elog(ERROR, "error during iter");
    }
    value = pstrdup(redis_scan_state->iter_reply->str);
    freeReplyObject(redis_scan_state->iter_reply);
    iter_redis_reply_status = redisGetReply(redis_scan_state->redis_ctx->connection_context, (void **)&redis_scan_state->iter_reply);
    if (iter_redis_reply_status == REDIS_ERR)
    {
        elog(ERROR, "error during iter");
    }
    ttl = (int)redis_scan_state->iter_reply->integer;
    freeReplyObject(redis_scan_state->iter_reply);
    slot_build_strings = (char **)palloc(3 * sizeof(char **));
    slot_build_strings[0] = keys[redis_scan_state->list_current];
    slot_build_strings[1] = value;
    buffer_ltoa = (char *)palloc(20 * sizeof(char)); // enough to hold int?
    pg_ltoa(ttl, buffer_ltoa);
    slot_build_strings[2] = buffer_ltoa;
    tuple = BuildTupleFromCStrings(att, slot_build_strings);
    redis_scan_state->list_current++;
    ExecStoreTuple(tuple, slot, InvalidBuffer, false);
    if (redis_scan_state->list_current == redis_scan_state->list_capacity && redis_scan_state->current_cursor != 0)
    {
        freeReplyObject(redis_scan_state->redis_reply);
        redis_scan_state->redis_reply = redisCommand(redis_scan_state->redis_ctx->connection_context, "scan %d match %s", redis_scan_state->current_cursor, redis_scan_state->search_name);
        if (redis_scan_state->redis_reply == NULL)
        {
            elog(ERROR, "failed in begin scan. we could not get reply from redis");
        }
        redis_scan_state->current_cursor = atoi(redis_scan_state->redis_reply->element[0]->str);
        redis_scan_state->list_capacity = (int)redis_scan_state->redis_reply->element[1]->elements;
        redis_scan_state->list_current = 0;
    }
    return slot;
}

void redisLinkReScanForeignScan(ForeignScanState *node)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    redisScanState *redis_scan_state = (redisScanState *)node->fdw_state;
    redis_scan_state->current_cursor = 0;
    redis_scan_state->list_capacity = 0;
    redis_scan_state->list_current = 0;
}

void redisLinkEndForeignScan(ForeignScanState *node)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    redisScanState *redis_scan_state = (redisScanState *)node->fdw_state;
    freeReplyObject(redis_scan_state->redis_reply);
    redisFree(redis_scan_state->redis_ctx->connection_context);
}

static List *redisLinkPlanForeignModify(PlannerInfo *root, ModifyTable *plan,
                                        Index resultRelation,
                                        int subplan_index)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    RangeTblEntry *rte;
    Oid foreigntableid;
    CmdType cmdtype = plan->operation;
    if (cmdtype != CMD_INSERT)
    {
        elog(ERROR, "Sorry, currently we only support insert operation.");
    }
    redisCtx *redis_ctx = (redisCtx *)palloc(sizeof(redisCtx));
    rte = planner_rt_fetch(resultRelation, root);
    foreigntableid = rte->relid;
    set_redis_ctx(foreigntableid, redis_ctx);
    return (List *)redis_ctx;
}

static void
redisLinkBeginForeignModify(ModifyTableState *mtstate,
                            ResultRelInfo *rinfo,
                            List *fdw_private,
                            int subplan_index,
                            int eflags)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    CmdType operation = mtstate->operation;
    if (operation != CMD_INSERT)
    {
        elog(ERROR, "Sorry, for now we only support insert. beginmodify");
    }
    redisCtx *redis_ctx = (redisCtx *)fdw_private;
    redisInsertState *insert_state = (redisInsertState *)palloc0(sizeof(redisInsertState));
    insert_state->redis_ctx = redis_ctx;
    insert_state->tmp_context = AllocSetContextCreate(mtstate->ps.state->es_query_cxt, "redis insert iter tmp memory", ALLOCSET_DEFAULT_SIZES);
    rinfo->ri_FdwState = (void *)insert_state;
}

static TupleTableSlot *redisLinkExecForeignInsert(EState *estate,
                                                  ResultRelInfo *rinfo,
                                                  TupleTableSlot *slot,
                                                  TupleTableSlot *planSlot)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    MemoryContext old_context;
    Datum datum;
    redisInsertState *insert_info = (redisInsertState *)rinfo->ri_FdwState;
    redisTableInfo *table_info = insert_info->redis_ctx->table_info;
    char *key;
    char *value;
    char *ttl;
    int128 ttl_in_long;
    int iter_redis_reply_status;
    if (insert_info->attmeta == NULL)
    {
        insert_info->attmeta = TupleDescGetAttInMetadata(slot->tts_tupleDescriptor);
    }
    old_context = MemoryContextSwitchTo(insert_info->tmp_context);
    for (int i = 0; i < table_info->column_num; i++)
    {
        bool isNull;
        datum = slot_getattr(slot, i + 1, &isNull);
        // TODO: we really need to set proper identifier in column instead of 0/1/2.
        switch (i)
        {
        case 0:
            key = DatumGetCString(OidFunctionCall1(table_info->columns[i].typoutput, datum));
            break;
        case 1:
            value = DatumGetCString(OidFunctionCall1(table_info->columns[i].typoutput, datum));
            break;
        case 2:
            if (isNull)
            {
                ttl_in_long = -1;
            }
            else
            {
                ttl = DatumGetCString(OidFunctionCall1(table_info->columns[i].typoutput, datum));
                ttl_in_long = atoll(ttl);
            }
            break;
        default:
            elog(ERROR, "????? we should not be here.");
            break;
        }
    }
    if (ttl_in_long == -1)
    {
        redisAppendCommand(insert_info->redis_ctx->connection_context, "set %s %s", key, value);
    }
    else
    {
        redisAppendCommand(insert_info->redis_ctx->connection_context, "set %s %s ex %ld", key, value, ttl_in_long);
    }
    insert_info->cached_cmd++;
    insert_info->current_buffered_data += strlen(key) + strlen(value);
    if (insert_info->current_buffered_data > MAX_CACHED_MEMORY)
    {
        while (insert_info->cached_cmd > 0)
        {
            iter_redis_reply_status = redisGetReply(insert_info->redis_ctx->connection_context, (void **)&insert_info->iter_reply);
            if (iter_redis_reply_status == REDIS_ERR)
            {
                elog(ERROR, "error during insert iter end");
            }
            freeReplyObject(insert_info->iter_reply);
            insert_info->cached_cmd--;
        }
        insert_info->current_buffered_data = 0;
        MemoryContextReset(CurrentMemoryContext);
    }
    MemoryContextSwitchTo(old_context);
    return slot;
}

static void
redisLinkEndForeignModify(EState *estate,
                          ResultRelInfo *rinfo)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    MemoryContext old_context;
    int iter_redis_reply_status;
    redisInsertState *insert_info = (redisInsertState *)rinfo->ri_FdwState;
    old_context = MemoryContextSwitchTo(insert_info->tmp_context);
    while (insert_info->cached_cmd > 0)
    {
        iter_redis_reply_status = redisGetReply(insert_info->redis_ctx->connection_context, (void **)&insert_info->iter_reply);
        if (iter_redis_reply_status == REDIS_ERR)
        {
            elog(ERROR, "error during insert iter end");
        }
        freeReplyObject(insert_info->iter_reply);
        insert_info->cached_cmd--;
    }
    redisFree(insert_info->redis_ctx->connection_context);
    MemoryContextReset(CurrentMemoryContext);
    MemoryContextSwitchTo(old_context);
}

static void
redisLinkBeginForeignInsert(ModifyTableState *mtstate,
                            ResultRelInfo *rinfo)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    CmdType operation = mtstate->operation;
    RangeTblEntry *rte;
    Index result_table_index;
    EState *estate;
    Oid foreigntableid;
    if (operation != CMD_INSERT)
    {
        elog(ERROR, "Sorry, for now we only support insert. beginmodify");
    }
    result_table_index = rinfo->ri_RangeTableIndex;
    estate = mtstate->ps.state;
    // get the rte of the foreign table.
    // because we don't support partition table. it seems for now, it is ok.
    rte = list_nth(estate->es_range_table, result_table_index - 1);
    foreigntableid = rte->relid;
    redisCtx *redis_ctx = (redisCtx *)palloc(sizeof(redisCtx));
    set_redis_ctx(foreigntableid, redis_ctx);
    redisInsertState *insert_state = (redisInsertState *)palloc0(sizeof(redisInsertState));
    insert_state->redis_ctx = redis_ctx;
    insert_state->tmp_context = AllocSetContextCreate(mtstate->ps.state->es_query_cxt, "redis insert iter tmp memory", ALLOCSET_DEFAULT_SIZES);
    rinfo->ri_FdwState = (void *)insert_state;
}

static void redisLinkEndForeignInsert(EState *estate,
                                      ResultRelInfo *rinfo)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    MemoryContext old_context;
    int iter_redis_reply_status;
    redisInsertState *insert_info = (redisInsertState *)rinfo->ri_FdwState;
    old_context = MemoryContextSwitchTo(insert_info->tmp_context);
    while (insert_info->cached_cmd > 0)
    {
        iter_redis_reply_status = redisGetReply(insert_info->redis_ctx->connection_context, (void **)&insert_info->iter_reply);
        if (iter_redis_reply_status == REDIS_ERR)
        {
            elog(ERROR, "error during insert iter end");
        }
        freeReplyObject(insert_info->iter_reply);
        insert_info->cached_cmd--;
    }
    redisFree(insert_info->redis_ctx->connection_context);
    MemoryContextReset(CurrentMemoryContext);
    MemoryContextSwitchTo(old_context);
}

Datum redis_link_handler(PG_FUNCTION_ARGS)
{
    FdwRoutine *froutine = makeNode(FdwRoutine);
    froutine->GetForeignRelSize = redisLinkGetForeignRelSize;
    froutine->GetForeignPaths = redisLinkGetForeignPaths;
    froutine->GetForeignPlan = redisLinkGetForeignPlan;
    froutine->BeginForeignScan = redisLinkBeginForeignScan;
    froutine->IterateForeignScan = redisLinkIterateForeignScan;
    froutine->ReScanForeignScan = redisLinkReScanForeignScan;
    froutine->EndForeignScan = redisLinkEndForeignScan;

    froutine->AddForeignUpdateTargets = NULL; // Currently we only want to support insert.
    froutine->PlanForeignModify = redisLinkPlanForeignModify;
    froutine->BeginForeignModify = redisLinkBeginForeignModify;
    froutine->ExecForeignInsert = redisLinkExecForeignInsert;
    froutine->EndForeignModify = redisLinkEndForeignModify;
    froutine->BeginForeignInsert = redisLinkBeginForeignInsert;
    froutine->EndForeignInsert = redisLinkEndForeignInsert;

    PG_RETURN_POINTER(froutine);
}