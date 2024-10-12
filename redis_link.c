
#include "postgres.h"
#include "fmgr.h"
#include "catalog/pg_foreign_table.h"
#include "catalog/pg_attrdef.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_foreign_table.h"
#include "access/reloptions.h"
#include "foreign/fdwapi.h"
#include "optimizer/pathnode.h"
#include "optimizer/restrictinfo.h"
#include "optimizer/planmain.h"
#include "fdw_redis.h"
#include "foreign/foreign.h"
#include "commands/defrem.h"
#include "utils/rel.h"
#include "catalog/pg_user_mapping.h"
#include "access/table.h"
#include "catalog/pg_operator.h"
#include "utils/syscache.h"
#include "utils/builtins.h"
#include "funcapi.h"

Datum redis_link_handler(PG_FUNCTION_ARGS);
Datum redis_link_validator(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(redis_link_handler);
PG_FUNCTION_INFO_V1(redis_link_validator);
PG_MODULE_MAGIC;

static HTAB *fdw_connection_hash = NULL;

typedef struct fdw_available_option
{
    char *option_name;
    Oid option_type;
} fdw_available_option;

static fdw_available_option fdw_various_options[] = {
    {"key", ForeignTableRelationId},
    {"value", ForeignTableRelationId},
    {"prefix", ForeignTableRelationId},
    {"host_port", ForeignServerRelationId},
    {"ttl", ForeignTableRelationId},
    {"ttl_type", ForeignTableRelationId},
    {"password", ForeignServerRelationId},
    {"table_type", ForeignTableRelationId},
    {"username", UserMappingRelationId},
    {"password", UserMappingRelationId},
    {NULL, InvalidOid}};

/*

Help functions

*/

// basically strdup but with palloc
char *fdw_strdup(char *s)
{
    char *r;
    r = (char *)palloc0(strlen(s) + 1);
    strcpy(r, s);
    return r;
}

// this function is used to set the host and port
// for hosts like "127.0.0.1:9001".
// the address must the same format. i.e. no space before or after the address.
void set_host_port(char *host_port, char **host, int *port)
{
    int iter = 0;

    while (host_port[iter] != ':')
    {
        iter++;
    }
    *host = (char *)palloc0(iter + 1);
    strncpy(*host, host_port, iter);
    (*host)[iter] = '\0';
    *port = atoi(&host_port[iter + 1]);
}

fdw_redisServer *fdw_make_fdw_redisServer(char *host_port)
{
    char *host;
    int port;
    fdw_redisServer *server;
    redisContext *c;
    set_host_port(host_port, &host, &port);
    server = (fdw_redisServer *)palloc(sizeof(fdw_redisServer));
    c = redisConnect(host, port);
    server->c = c;
    server->numCommand = 0;
    strcpy(server->host_port, host_port);
    pfree(host);
    return server;
}

// this function process host and port like "  127.0.0.1:9001    "
// into "127.0.0.1:9001"
char *process_host_port(char *host_port)
{
    char *res;
    int len = strlen(host_port);
    char *ss = (char *)palloc(len + 1);
    char *tmp = ss;
    strcpy(ss, host_port);

    while (len > 0 && ss[len - 1] == ' ')
    {
        ss[len - 1] = '\0';
        len--;
    }
    while (*ss == ' ')
    {
        ss++;
    }
    res = (char *)palloc0(strlen(ss) + 1);
    strcpy(res, ss);
    pfree(tmp);
    return res;
}

fdw_redisServer *getOneConnection(Oid foreigntableid)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    ListCell *cell;
    List *options;
    char *host_ports = NULL;
    char *host_tmp = NULL;
    fdw_redisServer *re_server;
    HASH_SEQ_STATUS status;
    // we need to init the connection hash table if this is the first time we use it.
    if (fdw_connection_hash == NULL)
    {
        ForeignTable *table;
        ForeignServer *server;
        HASHCTL ctl;
        ctl.keysize = FDW_SERVER_PORT_LEN;
        ctl.entrysize = sizeof(fdw_redisServer);
        fdw_connection_hash = hash_create("hash table for redis connections", FDW_NUM_SERVER, &ctl, HASH_ELEM | HASH_STRINGS);
        table = GetForeignTable(foreigntableid);
        server = GetForeignServer(table->serverid);
        options = server->options;
        foreach (cell, options)
        {
            DefElem *def = (DefElem *)lfirst(cell);
            if (strcmp(def->defname, "host_port") == 0)
            {
                host_ports = pstrdup(defGetString(def));
            }
        }
        if (host_ports == NULL)
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_OPTION_NAME_NOT_FOUND),
                    errmsg("host_port is not set properly"));
        }
        // the "host_ports" should look like
        // "  127.0.0.1:9001   ,    127.0.0.1:9002 , 127.0.0.1:9003   "
        // so we need to parse , first
        host_tmp = strtok(host_ports, ",");
        while (host_tmp != NULL)
        {

            char *host = process_host_port(host_tmp);

            fdw_redisServer *r_server = fdw_make_fdw_redisServer(host);
            bool found = false;

            fdw_redisServer *redis_server = (fdw_redisServer *)hash_search(fdw_connection_hash, host, HASH_ENTER, &found);
            //elog(INFO, "the host is %s", host);
            fdw_redisServer *new_server = (fdw_redisServer *)hash_search(fdw_connection_hash, host, HASH_FIND, &found);
            /*
            if (found)
            {
                elog(INFO, "found1! host is %s", host);
            }
            else
            {
                elog(INFO, "failed found1. Host is %s", host);
            }
            */

            redis_server->c = r_server->c;
            strcpy(redis_server->host_port, r_server->host_port);

            new_server = (fdw_redisServer *)hash_search(fdw_connection_hash, host, HASH_FIND, &found);
            /*
            if (found)
            {
                elog(INFO, "found1! host is %s", host);
            }
            else
            {
                elog(INFO, "failed found1. Host is %s", host);
            }
            */

            // redis_server->host_port = r_server->host_port;
            redis_server->numCommand = 0;
            pfree(r_server);
            host_tmp = strtok(NULL, ",");
        }
        pfree(host_ports);
    }
    hash_seq_init(&status, fdw_connection_hash);

    re_server = (fdw_redisServer *)hash_seq_search(&status);
    if (re_server == NULL)
    {
        ereport(ERROR,
                errcode(ERRCODE_FDW_UNABLE_TO_ESTABLISH_CONNECTION),
                errmsg("there is nothing in the connection hash table"));
    }
    hash_seq_term(&status);
    return re_server;
}

void set_scan_type_prefix(fdw_redisScanState *state, ForeignTable *table)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    List *options;
    ListCell *cell;
    char *s_type;
    char *prefix;
    char *ttl_type;
    options = table->options;
    state->type = FDW_TYPE_INVALID;
    s_type = NULL;
    foreach (cell, options)
    {
        DefElem *def = (DefElem *)lfirst(cell);
        if (strcmp(def->defname, "table_type") == 0)
        {
            s_type = defGetString(def);
            if (strcmp(s_type, "string") == 0)
            {
                state->type = FDW_TYPE_STRING;
            }
            else if (strcmp(s_type, "hash") == 0)
            {
                state->type = FDW_TYPE_HASH;
            }
            else if (strcmp(s_type, "set") == 0)
            {
                state->type = FDW_TYPE_SET;
            }
        }
        if (strcmp(def->defname, "prefix") == 0)
        {
            prefix = defGetString(def);
            state->prefix = pstrdup(prefix);
        }
        if (strcmp(def->defname, "ttl_type") == 0)
        {
            ttl_type = defGetString(def);
            if (strcmp(ttl_type, "second") == 0)
            {
                state->ttl_type = FDW_TTL_TYPE_SECOND;
            }
            else if (strcmp(ttl_type, "millisecond") == 0)
            {
                state->ttl_type = FDW_TTL_TYPE_MILLISECOND;
            }
            else
            {
                ereport(ERROR,
                        errcode(ERRCODE_FDW_INVALID_ATTRIBUTE_VALUE),
                        errmsg("wrong ttl_type for ttl type. The supported values are second/millisecond. The current value is %s", ttl_type));
            }
        }
    }
    if (state->type == FDW_TYPE_INVALID)
    {
        if (s_type == NULL)
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_UNABLE_TO_ESTABLISH_CONNECTION),
                    errmsg("table_type hasn't been set"));
        }
        else
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_UNABLE_TO_ESTABLISH_CONNECTION),
                    errmsg("Invalid table_type. Type is %s", s_type));
        }
    }
}

void set_scan_position(fdw_redisScanState *state, ForeignTable *table)
{

    Oid foreigntableid;
    Relation rel;
    TupleDesc tupleDesc;
    AttrNumber natts;
    AttrNumber attnum;
    List *options;
    ListCell *cell;
    //elog(INFO, "*** %s", __FUNCTION__);
    foreigntableid = table->relid;
    rel = table_open(foreigntableid, AccessShareLock);
    tupleDesc = RelationGetDescr(rel);
    natts = tupleDesc->natts;
    // elog(INFO, "natts is %d", natts);
    options = table->options;
    for (attnum = 1; attnum <= natts; attnum++)
    {
        Form_pg_attribute attr = TupleDescAttr(tupleDesc, attnum - 1);
        char *attname = pstrdup(NameStr(attr->attname));
        foreach (cell, options)
        {
            DefElem *def = (DefElem *)lfirst(cell);
            if (strcmp(def->defname, "key") == 0)
            {
                char *key_name = pstrdup(defGetString(def));
                if (strcmp(attname, key_name) == 0)
                {
                    state->key_pos = attnum;
                }
                pfree(key_name);
            }

            if (strcmp(def->defname, "value") == 0)
            {
                char *value_name = pstrdup(defGetString(def));
                if (strcmp(attname, value_name) == 0)
                {
                    state->val_pos = attnum;
                }
                pfree(value_name);
            }

            if (strcmp(def->defname, "ttl") == 0)
            {
                char *ttl_name = pstrdup(defGetString(def));
                if (strcmp(attname, ttl_name) == 0)
                {
                    state->ttl_pos = attnum;
                }
                pfree(ttl_name);
            }
        }
    }
    table_close(rel, AccessShareLock);
    if (state->key_pos == -1 || state->val_pos == -1)
    {
        ereport(ERROR,
                errcode(ERRCODE_FDW_UNABLE_TO_ESTABLISH_CONNECTION),
                errmsg("key or value is not set"));
    }
}

int get_operation_type(char *name)
{
    // //elog(INFO, "*** %s", __FUNCTION__);
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

void get_operation_infromation(OpExpr *expr, Oid *left_oid, Oid *right_oid, Oid *operation_type)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    // //elog(INFO, "*** %s", __FUNCTION__);
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

/*
void parse_where(fdw_redisRelationInfo *redis_info, Expr *expr)
{
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
            redis_info->where_clause = pstrdup(arg);
            for (int i = 0; i < strlen(redis_info->where_clause); i++)
            {
                if (redis_info->where_clause[i] == '%')
                {
                    redis_info->where_clause[i] = '*';
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
*/

/*
void set_where_clause(RelOptInfo *baserel, fdw_redisRelationInfo *redis_info, List *baserestrictinfo)
{
    Expr *expr;
    RestrictInfo *rinfo;
    ListCell *cell;
    if (baserestrictinfo == NULL)
    {
        redis_info->where_clause == NULL;
        return;
    }
    if (list_length(baserestrictinfo) == 1)
    {
        foreach (cell, baserestrictinfo)
        {
            rinfo = (RestrictInfo *)lfirst(cell);
            expr = rinfo->clause;
            parse_where(redis_info, expr);
        }
    }
    else
    {
        elog(ERROR, "sorry, currently we only support one where clues");
    }
}
*/

bool check_is_key_column(char *name, Oid foreigntableid)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    ForeignTable *foreign_table;
    List *table_options;
    ListCell *lc;
    foreign_table = GetForeignTable(foreigntableid);
    table_options = foreign_table->options;
    foreach (lc, table_options)
    {
        DefElem *def = (DefElem *)lfirst(lc);
        if (strcmp(def->defname, "key") == 0)
        {
            char *key_name = strVal(def->arg);
            if (strcmp(key_name, name) == 0)
            {
                // this is the key name!
                return true;
            }
        }
    }
    return false;
}

void set_where_clause(ForeignScanState *node, fdw_redisScanState *scan_state)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    ListCell *lc;
    List *qual;
    Expr *state;
    char *key;
    char *value;
    OpExpr *op;
    Node *left;
    Node *right;
    Index varattno;
    TupleDesc desc;
    bool push_down;
    Oid foreigntableid;
    qual = node->ss.ps.plan->qual;
    foreigntableid = RelationGetRelid(node->ss.ss_currentRelation);
    push_down = false;
    desc = node->ss.ss_currentRelation->rd_att;
    scan_state->match_part = makeStringInfo();
    switch (scan_state->type)
    {
    // if the table type is string, then we need to mak
    case FDW_TYPE_STRING:
        if (scan_state->prefix != NULL)
        {
            appendStringInfoString(scan_state->match_part, scan_state->prefix);
        }
        break;
    default:
        break;
    }

    if (qual == NULL)
    {
        // if there is no qual, that means we are executing something like
        // select * from tablename. We need to append * in the end of the match_part.
        // So, we can get all the info from the
        if (scan_state->prefix != NULL)
        {
            appendStringInfoString(scan_state->match_part, "*");
        }
        return;
    }
    // we only push down 1 condition.
    foreach (lc, qual)
    {
        state = lfirst(lc);
        if (IsA(state, OpExpr))
        {
            op = (OpExpr *)state;
            if (list_length(op->args) != 2)
            {
                ereport(ERROR,
                        errcode(ERRCODE_FDW_INVALID_ATTRIBUTE_VALUE),
                        errmsg("the parameters of where condition is not 2"));
            }
            left = list_nth(op->args, 0);
            varattno = ((Var *)left)->varattno;
            right = list_nth(op->args, 1);
            if (IsA(right, Const))
            {
                key = NameStr(TupleDescAttr(desc, varattno - 1)->attname);
                value = TextDatumGetCString(((Const *)right)->constvalue);
                if (check_is_key_column(key, foreigntableid))
                {

                    appendStringInfoString(scan_state->match_part, value);
                    for (int i = 0; i < scan_state->match_part->len; i++)
                    {
                        if (scan_state->match_part->data[i] == '%')
                        {
                            scan_state->match_part->data[i] = '*';
                        }
                    }
                    push_down = true;
                }
            }
        }
        if (push_down == true)
        {
            break;
        }
    }
}

List *make_connection_list(HTAB *connection_hash)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    List *connection_list;
    HASH_SEQ_STATUS status;
    fdw_redisServer *redis_server;
    connection_list = NIL;
    hash_seq_init(&status, connection_hash);
    redis_server = (fdw_redisServer *)hash_seq_search(&status);
    while (redis_server != NULL)
    {
        connection_list = lappend(connection_list, (void *)redis_server);
        redis_server = (fdw_redisServer *)hash_seq_search(&status);
    }
    return connection_list;
}

/*

functions for scan










*/

// we need to add
void set_scan_command(fdw_redisScanState *scan_state, int current_pos)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    StringInfo buf;
    buf = makeStringInfo();
    switch (scan_state->type)
    {
    case FDW_TYPE_STRING:
        appendStringInfo(buf, "scan %d ", current_pos);
        break;

    default:
        break;
    }
    // elog(INFO, "the size of string buffer is: %d", buf->len);
    if (buf->len == 0)
    {
        ereport(ERROR,
                errcode(ERRCODE_FDW_UNABLE_TO_ESTABLISH_CONNECTION),
                errmsg("currenlty, this table type is not supported."));
    }
    appendStringInfoString(buf, "match ");
    appendStringInfoString(buf, scan_state->match_part->data);
    // appendStringInfo(buf, scan_state->match_part->data);
    scan_state->scan_command = buf;
    // elog(INFO, "scan command to redis is %s",scan_state->scan_command->data);
    // elog(INFO, "match_key is: %s", scan_state->match_part->data);
}

bool scan_is_done(fdw_redisScanState *state)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    if (state->connection_list == NULL)
    {
        return true;
    }
    return false;
}

StringInfo scan_command_withPos(fdw_redisScanState *state, int pos)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    StringInfo buf = (StringInfo)palloc(sizeof(StringInfoData));
    initStringInfo(buf);
    switch (state->type)
    {
    case FDW_TYPE_STRING:
        appendStringInfoString(buf, "scan ");
        break;
    // when the table type is hash, we use prefix as the tablename,
    // for example, hscan prefix 0 match *
    case FDW_TYPE_HASH:
        appendStringInfo(buf, "hscan %s ", state->prefix);
        break;
    default:
        ereport(ERROR,
                errcode(ERRCODE_FDW_REPLY_HANDLE),
                errmsg("unsupport table type"));
        break;
    }
    appendStringInfo(buf, "%d match ", pos);
    appendStringInfoString(buf, state->match_part->data);
    return buf;
}

bool replyWithMOVED(redisReply *r)
{
    if (r == NULL)
    {
        return false;
    }
    if (r->type != REDIS_REPLY_ERROR)
    {
        return false;
    }
    if (strlen(r->str) <= strlen("MOVED "))
    {
        return false;
    }
    if (strncmp(r->str, "MOVED ", strlen("MOVED ")) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

char **stringReturnTuple(fdw_redisScanState *status)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    redisReply *r = status->r;
    char *item;
    char **res;
    redisContext *c;
    fdw_redisServer *server;
    ListCell *cell;
    redisReply *tmp;
    long long ttl;
    char *buffer; // used for conversion from long long ttl to char.
    if (status->type != FDW_TYPE_STRING)
    {
        ereport(ERROR,
                errcode(ERRCODE_FDW_UNABLE_TO_CREATE_REPLY),
                errmsg("the table type is not string. Please check why the string function is invoked"));
    }

    item = r->element[1]->element[status->current_pos]->str;
    if (status->ttl_pos == -1)
    {
        res = (char **)palloc0(2 * sizeof(char **));
    }
    else
    {
        res = (char **)palloc0(3 * sizeof(char **));
    }
    cell = list_last_cell(status->connection_list);
    server = lfirst(cell);
    c = server->c;
    tmp = (redisReply *)redisCommand(c, "get %s", item);
    res[status->key_pos - 1] = pstrdup(item);
    res[status->val_pos - 1] = pstrdup(tmp->str);
    if (status->ttl_pos != -1)
    {
        freeReplyObject(tmp);
        tmp = (redisReply *)redisCommand(c, "ttl %s", item);
        if (tmp == NULL || tmp->type == REDIS_ERR)
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_REPLY_HANDLE),
                    errmsg("could not read ttl result from redis server."));
        }
        ttl = tmp->integer;
        buffer = (char *)palloc(52 * sizeof(char)); // enough to hold int?
        pg_lltoa(ttl, buffer);
        res[status->ttl_pos - 1] = buffer;
    }
    freeReplyObject(tmp);
    return res;
}

char *stringScanCommand(fdw_redisScanState *status)
{
    StringInfo command = (StringInfo)palloc0(sizeof(StringInfoData));
    initStringInfo(command);
    appendStringInfo(command, "scan %d match ", status->next_pos);
    appendStringInfoString(command, status->match_part->data);
    return command->data;
}

char **fdw_redisReadFlow(fdw_redisScanState *flow)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    ListCell *cell;
    List *connections;
    redisContext *c;
    fdw_redisServer *server;
    redisReply *r;
    int arr_len = -1;
    char *(*scanCommand)(fdw_redisScanState *flow) = flow->scanCommand;
    char **(*returnTuple)(fdw_redisScanState *flow) = flow->returnTuple;
    connections = flow->connection_list;
    if (list_length(connections) == 0)
    {
        return false;
    }
    cell = list_last_cell(connections);
    server = lfirst(cell);
    c = server->c;
    // in this connection, we haven't requested data yet.
    // let's request the data and let the subsequent call to handle it.
    if (flow->next_pos == -1)
    {
        if (flow->r != NULL)
        {
            freeReplyObject(flow->r);
        }
        flow->next_pos = 0;
        char *command = scanCommand(flow);
        flow->r = (redisReply *)redisCommand(c, command);
        r = flow->r;
        if (r == NULL)
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_REPLY_HANDLE),
                    errmsg("we cannot get data from redis server."));
        }
        if (r->type == REDIS_REPLY_ERROR && replyWithMOVED(r))
        {
            flow->connection_list = list_delete_last(flow->connection_list);
            flow->next_pos = -1;
            return fdw_redisReadFlow(flow);
        }
        flow->next_pos = atoi(r->element[0]->str);
        flow->current_pos = 0;
        return fdw_redisReadFlow(flow);
    }
    // we have reached the end of one iter of request.
    // it is time to request data again from redis server
    arr_len = flow->r->element[1]->elements;
    if (flow->next_pos != 0 && flow->current_pos == arr_len)
    {
        char *command = scanCommand(flow);
        freeReplyObject(flow->r);
        flow->r = (redisReply *)redisCommand(c, command);
        r = flow->r;
        if (r == NULL)
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_REPLY_HANDLE),
                    errmsg("we cannot get data from redis server."));
        }
        if (r->type == REDIS_REPLY_ERROR && replyWithMOVED(r))
        {
            flow->connection_list = list_delete_last(flow->connection_list);
            return fdw_redisReadFlow(flow);
        }
        flow->next_pos = atoi(r->element[0]->str);
        flow->current_pos = 0;
        return fdw_redisReadFlow(flow);
    }
    // for this connection, we are done.
    if (flow->next_pos == 0 && flow->current_pos == arr_len)
    {
        flow->connection_list = list_delete_last(flow->connection_list);
        flow->next_pos = -1;
        flow->current_pos = 0;
        freeReplyObject(flow->r);
        flow->r = NULL;
        return fdw_redisReadFlow(flow);
    }
    // For normal scenarios
    char **tuple;
    tuple = returnTuple(flow);
    flow->current_pos++;
    return tuple;
}

char **hashReturnTuple(fdw_redisScanState *status)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    redisReply *r = status->r;
    char *item_key;
    char *item_val;
    char **res;
    redisContext *c;
    fdw_redisServer *server;
    ListCell *cell;
    redisReply *tmp;
    long long ttl;
    char *buffer; // used for conversion from long long ttl to char.
    if (status->type != FDW_TYPE_HASH)
    {
        ereport(ERROR,
                errcode(ERRCODE_FDW_UNABLE_TO_CREATE_REPLY),
                errmsg("the table type is not string. Please check why the hash function is invoked"));
    }
    // for hash type, the key and value are included in a normal retrun.
    item_key = r->element[1]->element[status->current_pos++]->str;
    // at the generic read flow side, the current_pos will be added 1.
    item_val = r->element[1]->element[status->current_pos]->str;
    if (status->ttl_pos == -1)
    {
        res = (char **)palloc0(2 * sizeof(char **));
    }
    else
    {
        res = (char **)palloc0(3 * sizeof(char **));
    }
    cell = list_last_cell(status->connection_list);
    server = lfirst(cell);
    c = server->c;
    res[status->key_pos - 1] = pstrdup(item_key);
    res[status->val_pos - 1] = pstrdup(item_val);
    if (status->ttl_pos != -1)
    {
        tmp = (redisReply *)redisCommand(c, "ttl %s", status->prefix);
        if (tmp == NULL || tmp->type == REDIS_ERR)
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_REPLY_HANDLE),
                    errmsg("could not read ttl result from redis server."));
        }
        ttl = tmp->integer;
        buffer = (char *)palloc(52 * sizeof(char)); // enough to hold int?
        pg_lltoa(ttl, buffer);
        res[status->ttl_pos - 1] = buffer;
        freeReplyObject(tmp);
    }
    return res;
}

char *hashScanCommand(fdw_redisScanState *status)
{
    StringInfo command = (StringInfo)palloc0(sizeof(StringInfoData));
    initStringInfo(command);
    appendStringInfo(command, "hscan %s %d match %s", status->prefix, status->next_pos, status->match_part->data);
    return command->data;
}

char **setReturnTuple(fdw_redisScanState *status)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    redisReply *r = status->r;
    char *item_key;
    char *item_val;
    char **res;
    redisContext *c;
    fdw_redisServer *server;
    ListCell *cell;
    redisReply *tmp;
    long long ttl;
    char *buffer; // used for conversion from long long ttl to char.
    if (status->type != FDW_TYPE_SET)
    {
        ereport(ERROR,
                errcode(ERRCODE_FDW_UNABLE_TO_CREATE_REPLY),
                errmsg("the table type is not string. Please check why the hash function is invoked"));
    }
    // for set type, the key is the table name.
    item_key = status->prefix;
    // at the generic read flow side, the current_pos will be added 1.
    item_val = r->element[1]->element[status->current_pos]->str;
    if (status->ttl_pos == -1)
    {
        res = (char **)palloc0(2 * sizeof(char **));
    }
    else
    {
        res = (char **)palloc0(3 * sizeof(char **));
    }
    cell = list_last_cell(status->connection_list);
    server = lfirst(cell);
    c = server->c;
    res[status->key_pos - 1] = pstrdup(item_key);
    res[status->val_pos - 1] = pstrdup(item_val);
    if (status->ttl_pos != -1)
    {
        tmp = (redisReply *)redisCommand(c, "ttl %s", status->prefix);
        if (tmp == NULL || tmp->type == REDIS_ERR)
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_REPLY_HANDLE),
                    errmsg("could not read ttl result from redis server."));
        }
        ttl = tmp->integer;
        buffer = (char *)palloc(52 * sizeof(char)); // enough to hold int?
        pg_lltoa(ttl, buffer);
        res[status->ttl_pos - 1] = buffer;
        freeReplyObject(tmp);
    }
    return res;
}

char *setScanCommand(fdw_redisScanState *status)
{
    StringInfo command = (StringInfo)palloc0(sizeof(StringInfoData));
    initStringInfo(command);
    appendStringInfo(command, "sscan %s %d match %s", status->prefix, status->next_pos, status->match_part->data);
    return command->data;
}

/*
For insert operations.













*/

bool hostIP(redisReply *r, char **hostIP)
{
    char *res;
    char *s;
    if (r == NULL || r->type != REDIS_REPLY_ERROR)
    {
        return false;
    }
    if (strlen(r->str) <= strlen("MOVED "))
    {
        return false;
    }
    if (strncmp(r->str, "MOVED ", strlen("MOVED ")) != 0)
    {
        return false;
    }
    int spaceCount = 0;
    int i = 0;
    s = r->str;
    while (spaceCount < 2)
    {
        if (s[i] == ' ')
        {
            spaceCount++;
        }
        i++;
    }
    res = (char *)palloc0(strlen(s) - i + 2);
    strcpy(res, &s[i]);
    *hostIP = res;
    return true;
}

void fdw_redisInsert_setTyp(fdw_redisInsertState *flow, Oid foreigntableid)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    Relation rel;
    TupleDesc tupledesc;
    AttrNumber natts;
    AttrNumber attnum;
    Oid typeid;
    HeapTuple tuple;
    rel = table_open(foreigntableid, AccessShareLock);
    tupledesc = RelationGetDescr(rel);
    natts = tupledesc->natts;
    flow->typinput = (Oid *)palloc0(sizeof(Oid) * natts);
    flow->typoutput = (Oid *)palloc0(sizeof(Oid) * natts);
    for (attnum = 1; attnum <= natts; attnum++)
    {
        Form_pg_attribute att = TupleDescAttr(tupledesc, attnum - 1);
        typeid = att->atttypid;
        tuple = SearchSysCache1(TYPEOID, ObjectIdGetDatum(typeid));
        if (!HeapTupleIsValid(tuple))
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_REPLY_HANDLE),
                    errmsg("Error when open the catalog for inout function."));
        }
        Form_pg_type pg_type = (Form_pg_type)GETSTRUCT(tuple);
        flow->typinput[attnum - 1] = pg_type->typinput;
        flow->typoutput[attnum - 1] = pg_type->typoutput;
        ReleaseSysCache(tuple);
    }
    table_close(rel, AccessShareLock);
}

void fdw_redisInsert_setPos(fdw_redisInsertState *flow, Oid foreigntableid)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    ForeignTable *table;
    List *options;
    ListCell *cell;
    Relation rel;
    TupleDesc tupledesc;
    AttrNumber natts;
    AttrNumber attnum;
    table = GetForeignTable(foreigntableid);
    options = table->options;
    rel = table_open(foreigntableid, AccessShareLock);
    tupledesc = RelationGetDescr(rel);
    natts = tupledesc->natts;
    for (attnum = 1; attnum <= natts; attnum++)
    {
        Form_pg_attribute attr = TupleDescAttr(tupledesc, attnum - 1);
        char *attname = pstrdup(NameStr(attr->attname));
        foreach (cell, options)
        {
            DefElem *def = (DefElem *)lfirst(cell);
            if (strcmp(def->defname, "key") == 0)
            {
                char *key_name = pstrdup(defGetString(def));
                if (strcmp(attname, key_name) == 0)
                {
                    flow->key_pos = attnum;
                }
                pfree(key_name);
            }

            if (strcmp(def->defname, "value") == 0)
            {
                char *value_name = pstrdup(defGetString(def));
                if (strcmp(attname, value_name) == 0)
                {
                    flow->val_pos = attnum;
                }
                pfree(value_name);
            }

            if (strcmp(def->defname, "ttl") == 0)
            {
                char *ttl_name = pstrdup(defGetString(def));
                if (strcmp(attname, ttl_name) == 0)
                {
                    flow->ttl_pos = attnum;
                }
                pfree(ttl_name);
            }

            if (strcmp(def->defname, "table_type") == 0 && flow->tableType != FDW_TYPE_INVALID)
            {

                char *s_type = defGetString(def);
                if (strcmp(s_type, "string") == 0)
                {
                    flow->tableType = FDW_TYPE_STRING;
                }
                else if (strcmp(s_type, "hash") == 0)
                {
                    flow->tableType = FDW_TYPE_HASH;
                }
                else if (strcmp(s_type, "set") == 0)
                {
                    flow->tableType = FDW_TYPE_SET;
                }
            }
        }
    }
    table_close(rel, AccessShareLock);
    if (flow->key_pos == -1 || flow->val_pos == -1)
    {
        ereport(ERROR,
                errcode(ERRCODE_FDW_UNABLE_TO_ESTABLISH_CONNECTION),
                errmsg("key or value is not set"));
    }
}

void fdw_redisInsert_setPrefix(fdw_redisInsertState *flow, Oid foreigntableid)
{
    ForeignTable *table;
    List *options;
    ListCell *cell;
    char *prefix;
    table = GetForeignTable(foreigntableid);
    options = table->options;
    flow->prefix = NULL;
    foreach (cell, options)
    {
        DefElem *def = (DefElem *)lfirst(cell);
        if (strcmp(def->defname, "prefix") == 0)
        {
            prefix = defGetString(def);
            flow->prefix = pstrdup(prefix);
        }
    }
}

char **string_fdw_insertCommand(fdw_redisInsertState *flow, char *key, char *val, char *ttl)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    StringInfo buf;
    // for string table type, we only need 1 command to set the key/val and ttl.
    char **res = (char **)palloc0(sizeof(char *) * 2);
    buf = (StringInfo)palloc0(sizeof(StringInfoData));
    initStringInfo(buf);
    if (ttl)
    {
        appendStringInfo(buf, "set %s%s %s ex %s", flow->prefix, key, val, ttl);
    }
    else
    {
        appendStringInfo(buf, "set %s%s %s ex %s", flow->prefix, key, val, ttl);
    }
    res[0] = buf->data;
    res[1] = NULL;
    return res;
}

char **hash_fdw_insertCommand(fdw_redisInsertState *flow, char *key, char *val, char *ttl)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    StringInfo buf;
    StringInfo ttl_info;
    char **res;
    buf = (StringInfo)palloc0(sizeof(StringInfoData));
    ttl_info = (StringInfo)palloc0(sizeof(StringInfoData));
    initStringInfo(buf);
    initStringInfo(ttl_info);
    appendStringInfo(buf, "hset %s %s %s", flow->prefix, key, val);
    res = (char **)palloc0(sizeof(char *) * 3);
    res[0] = buf->data;
    if (ttl)
    {
        appendStringInfo(ttl_info, "expire %s %s", flow->prefix, ttl);
        res[1] = ttl_info->data;
    }
    return res;
}

void fdw_redisInsertFlow(struct fdw_redisInsertState *flow)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    redisReply *r;
    char *command;
    redisContext *c;
    ListCell *lc;
    fdw_redisServer *server;
    foreach (lc, flow->commandQueue1)
    {
        fdw_insertCommandC *commandc = (fdw_insertCommandC *)lfirst(lc);
        c = commandc->c;
        command = commandc->command;
        redisAppendCommand(c, command);
    }
    foreach (lc, flow->commandQueue1)
    {
        fdw_insertCommandC *commandc = (fdw_insertCommandC *)lfirst(lc);
        c = commandc->c;
        command = commandc->command;
        redisGetReply(c, (void **)&r);
        if (replyWithMOVED(r))
        {
            bool hasFound = false;
            char *host_ip = NULL;
            if (!hostIP(r, &host_ip))
            {
                ereport(ERROR,
                        errcode(ERRCODE_FDW_REPLY_HANDLE),
                        errmsg("host in reply message could not be parsed. the host and IP was %s", host_ip));
            }
            server = (fdw_redisServer *)hash_search(fdw_connection_hash, host_ip, HASH_FIND, &hasFound);
            if (!hasFound)
            {
                ereport(ERROR,
                        errcode(ERRCODE_FDW_REPLY_HANDLE),
                        errmsg("host:ip could not be found. the host is %s", host_ip));
            }

            commandc->c = server->c;
            flow->commandQueue2 = lappend(flow->commandQueue2, (void *)commandc);
            //elog(INFO, "appened command %s to %s:%d ", commandc->command, commandc->c->tcp.host, commandc->c->tcp.port);
        }
        freeReplyObject(r);
    }
    foreach (lc, flow->commandQueue2)
    {
        fdw_insertCommandC *commandc = (fdw_insertCommandC *)lfirst(lc);
        c = commandc->c;
        command = commandc->command;
        redisAppendCommand(c, command);
    }
    foreach (lc, flow->commandQueue2)
    {
        fdw_insertCommandC *commandc = (fdw_insertCommandC *)lfirst(lc);
        c = commandc->c;
        command = commandc->command;
        redisGetReply(c, (void **)&r);
        if (r == NULL || r->type == REDIS_REPLY_ERROR)
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_REPLY_HANDLE),
                    errmsg("reply object is ERROR."));
        }
        freeReplyObject(r);
    }
}

/*




















 * FDW callback routines
 */

void fdw_redislinkGetForeignRelSize(PlannerInfo *root,
                                    RelOptInfo *baserel,
                                    Oid foreigntableid);

void fdw_redislinkGetForeignPaths(PlannerInfo *root,
                                  RelOptInfo *baserel,
                                  Oid foreigntableid);
ForeignScan *fdw_redislinkGetForeignPlan(PlannerInfo *root,
                                         RelOptInfo *baserel,
                                         Oid foreigntableid,
                                         ForeignPath *best_path,
                                         List *tlist,
                                         List *scan_clauses,
                                         Plan *outer_plan);

void fdw_redislinkBeginForeignScan(ForeignScanState *node,
                                   int eflags);

TupleTableSlot *fdw_redislinkIterateForeignScan(ForeignScanState *node);

void fdw_redislinkReScanForeignScan(ForeignScanState *node);

void fdw_redislinkEndForeignScan(ForeignScanState *node);

List *fdw_redislinkPlanForeignModify(PlannerInfo *root,
                                     ModifyTable *plan,
                                     Index resultRelation,
                                     int subplan_index);

List *fdw_redislinkPlanForeignModify(PlannerInfo *root,
                                     ModifyTable *plan,
                                     Index resultRelation,
                                     int subplan_index);
void fdw_redislinkBeginForeignModify(ModifyTableState *mtstate,
                                     ResultRelInfo *rinfo,
                                     List *fdw_private,
                                     int subplan_index,
                                     int eflags);
TupleTableSlot *
fdw_redislinkExecForeignInsert(EState *estate,
                               ResultRelInfo *rinfo,
                               TupleTableSlot *slot,
                               TupleTableSlot *planSlot);

void fdw_redislinkEndForeignModify(EState *estate, ResultRelInfo *rinfo);

// herler functions
bool fdw_is_valid_options(char *option_name, Oid option_type);

bool fdw_is_valid_options(char *option_name, Oid option_type)
{
    fdw_available_option *opt;
    for (opt = fdw_various_options; opt->option_name != NULL; opt++)
    {
        if (strcmp(opt->option_name, option_name) == 0 && opt->option_type == option_type)
        {
            return true;
        }
    }
    return false;
}

Datum redis_link_validator(PG_FUNCTION_ARGS)
{
    List *option_list = untransformRelOptions(PG_GETARG_DATUM(0));
    Oid option_type = PG_GETARG_OID(1);
    ListCell *cell;
    foreach (cell, option_list)
    {
        DefElem *def = (DefElem *)lfirst(cell);
        if (!fdw_is_valid_options(def->defname, option_type))
        {
            ereport(ERROR,
                    errcode(ERRCODE_FDW_OPTION_NAME_NOT_FOUND),
                    errmsg("the setting is not supported. The name is %s, the option type is %d", def->defname, option_type));
        }
    }
    PG_RETURN_VOID();
}

Datum redis_link_handler(PG_FUNCTION_ARGS)
{

    FdwRoutine *froutine = makeNode(FdwRoutine);

    froutine->GetForeignRelSize = fdw_redislinkGetForeignRelSize;
    froutine->GetForeignPaths = fdw_redislinkGetForeignPaths;
    froutine->GetForeignPlan = fdw_redislinkGetForeignPlan;
    froutine->BeginForeignScan = fdw_redislinkBeginForeignScan;
    froutine->IterateForeignScan = fdw_redislinkIterateForeignScan;
    froutine->ReScanForeignScan = fdw_redislinkReScanForeignScan;
    froutine->EndForeignScan = fdw_redislinkEndForeignScan;

    froutine->AddForeignUpdateTargets = NULL; // Currently we only want to support insert.
    froutine->PlanForeignModify = fdw_redislinkPlanForeignModify;
    froutine->BeginForeignModify = fdw_redislinkBeginForeignModify;
    froutine->ExecForeignInsert = fdw_redislinkExecForeignInsert;
    froutine->EndForeignModify = fdw_redislinkEndForeignModify;
    PG_RETURN_POINTER(froutine);
    /*
    froutine->BeginForeignInsert = redisLinkBeginForeignInsert;
    froutine->EndForeignInsert = redisLinkEndForeignInsert;

    PG_RETURN_POINTER(froutine);
    */
}

// in this function, perhaps we should not connect to redis.
// the relation size should be returned from analyze.
void fdw_redislinkGetForeignRelSize(PlannerInfo *root,
                                    RelOptInfo *baserel,
                                    Oid foreigntableid)
{
    // fdw_redisRelationInfo *rel_info;
    //elog(INFO, "*** %s", __FUNCTION__);
    baserel->rows = 100;
    // rel_info = (fdw_redisRelationInfo *)palloc0(sizeof(fdw_redisRelationInfo));
    /*
    if (root->parse->commandType == CMD_SELECT)
    {
        elog(INFO, "This is a select query");
        set_where_clause(baserel, rel_info, baserel->baserestrictinfo);
    }
    baserel->fdw_private = (void *)rel_info;
    */
    // baserel->attr_widths = 100;
}

void fdw_redislinkGetForeignPaths(PlannerInfo *root,
                                  RelOptInfo *baserel,
                                  Oid foreigntableid)
{
    Path *path = (Path *)create_foreignscan_path(root, baserel, NULL, baserel->rows, 100, 100, NIL, NULL, NULL, NIL);
    add_path(baserel, path);
}

ForeignScan *fdw_redislinkGetForeignPlan(PlannerInfo *root,
                                         RelOptInfo *baserel,
                                         Oid foreigntableid,
                                         ForeignPath *best_path,
                                         List *tlist,
                                         List *scan_clauses,
                                         Plan *outer_plan)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    scan_clauses = extract_actual_clauses(scan_clauses, NULL);
    return make_foreignscan(tlist, scan_clauses, baserel->relid, NIL, NIL, NIL, NIL, NULL);
}

void fdw_redislinkBeginForeignScan(ForeignScanState *node,
                                   int eflags)
{
    //elog(INFO, "*** %s", __FUNCTION__);

    Relation table_rel;
    Oid foreigntableid;
    // fdw_redisServer *redis_server;
    fdw_redisScanState *scan_state;
    ForeignTable *foreign_table;
    // //elog(INFO, "*** %s", __FUNCTION__);
    table_rel = node->ss.ss_currentRelation;
    foreigntableid = RelationGetRelid(table_rel);
    // in this fucntion, let's polulate the connection hash table.
    getOneConnection(foreigntableid);
    scan_state = (fdw_redisScanState *)palloc0(sizeof(fdw_redisScanState));
    scan_state->current_pos = -1;
    scan_state->key_pos = -1;
    scan_state->val_pos = -1;
    scan_state->ttl_pos = -1;
    scan_state->r = NULL;
    scan_state->prefix = NULL;
    scan_state->next_pos = -1;
    foreign_table = GetForeignTable(foreigntableid);
    set_scan_type_prefix(scan_state, foreign_table);
    set_scan_position(scan_state, foreign_table);
    set_where_clause(node, scan_state);
    node->fdw_state = (void *)scan_state;
    scan_state->connection_list = make_connection_list(fdw_connection_hash);
    scan_state->current_cell = list_tail(scan_state->connection_list);
    switch (scan_state->type)
    {
    case FDW_TYPE_STRING:
        scan_state->scanCommand = stringScanCommand;
        scan_state->returnTuple = stringReturnTuple;
        break;
    case FDW_TYPE_HASH:
        scan_state->scanCommand = hashScanCommand;
        scan_state->returnTuple = hashReturnTuple;
        break;
    case FDW_TYPE_SET:
        scan_state->scanCommand = setScanCommand;
        scan_state->returnTuple = setReturnTuple;
        break;
    default:
        ereport(ERROR,
                errcode(ERRCODE_FDW_REPLY_HANDLE),
                errmsg("not support this table type."));
        break;
    }
    // elog(INFO, "*** connection is done");
    return;
}

TupleTableSlot *fdw_redislinkIterateForeignScan(ForeignScanState *node)
{
    // //elog(INFO, "*** %s", __FUNCTION__);
    AttInMetadata *att;
    HeapTuple tuple;
    char **res;
    char **slot_build_string;
    List *qual;
    int prefix_len;
    TupleTableSlot *slot = node->ss.ss_ScanTupleSlot;
    fdw_redisScanState *scan_state = (fdw_redisScanState *)node->fdw_state;
    att = TupleDescGetAttInMetadata(node->ss.ss_currentRelation->rd_att);
    ExecClearTuple(slot);
    /*
    if (!scan_get_next_data(scan_state, &key, &val, &ttl))
    {
        return slot;
    }
    */
    res = fdw_redisReadFlow(scan_state);
    if (res == NULL)
    {
        return slot;
    }
    if (scan_state->ttl_pos == -1)
    {
        slot_build_string = (char **)palloc0(2 * sizeof(char **));
    }
    else
    {
        slot_build_string = (char **)palloc0(3 * sizeof(char **));
    }
    qual = node->ss.ps.plan->qual;
    // if we have prefix, we should not inclued the prefix in the key list,
    // as the result will be blocked by recheck node.
    // here for non-string typed table, we don't need to skip the prefix.
    if (scan_state->prefix != NULL && scan_state->type == FDW_TYPE_STRING) // && qual != NULL)
    {
        prefix_len = strlen(scan_state->prefix);
        slot_build_string[scan_state->key_pos - 1] = &res[scan_state->key_pos - 1][prefix_len];
    }
    else
    {
        slot_build_string[scan_state->key_pos - 1] = res[scan_state->key_pos - 1];
    }
    slot_build_string[scan_state->val_pos - 1] = res[scan_state->val_pos - 1];
    if (scan_state->ttl_pos != -1)
    {
        slot_build_string[scan_state->ttl_pos - 1] = res[scan_state->ttl_pos - 1];
    }

    tuple = BuildTupleFromCStrings(att, slot_build_string);
    ExecStoreHeapTuple(tuple, slot, false);
    //elog(INFO, "+++++++ the key is %s, and the val is %s", res[scan_state->key_pos - 1], res[scan_state->val_pos - 1]);
    return slot;
}

void fdw_redislinkReScanForeignScan(ForeignScanState *node)
{
    return;
}

void fdw_redislinkEndForeignScan(ForeignScanState *node)
{
    return;
}

List *fdw_redislinkPlanForeignModify(PlannerInfo *root,
                                     ModifyTable *plan,
                                     Index resultRelation,
                                     int subplan_index)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    RangeTblEntry *rte;
    Oid foreigntableid;
    fdw_redisInsertState *flow = (fdw_redisInsertState *)palloc0(sizeof(fdw_redisInsertState));
    rte = planner_rt_fetch(resultRelation, root);
    foreigntableid = rte->relid;
    flow->foreigntableid = foreigntableid;
    return (List *)flow;
}

void fdw_redislinkBeginForeignModify(ModifyTableState *mtstate,
                                     ResultRelInfo *rinfo,
                                     List *fdw_private,
                                     int subplan_index,
                                     int eflags)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    fdw_redisServer *server = NULL;
    redisContext *c = NULL;
    CmdType cmdtype = mtstate->operation;
    fdw_redisInsertState *flow = (fdw_redisInsertState *)fdw_private;
    if (cmdtype != CMD_INSERT)
    {
        ereport(ERROR,
                errcode(ERRCODE_FDW_OPTION_NAME_NOT_FOUND),
                errmsg("currently we only support insert for modify opeartions"));
    }
    flow->commandQueue1 = NULL;
    flow->commandQueue2 = NULL;
    flow->key_pos = -1;
    flow->val_pos = -1;
    flow->ttl_pos = -1;
    fdw_redisInsert_setPos(flow, flow->foreigntableid);
    fdw_redisInsert_setTyp(flow, flow->foreigntableid);
    fdw_redisInsert_setPrefix(flow, flow->foreigntableid);
    switch (flow->tableType)
    {
    case FDW_TYPE_STRING:
        flow->fdw_insertCommand = string_fdw_insertCommand;
        break;
    case FDW_TYPE_HASH:
        flow->fdw_insertCommand = hash_fdw_insertCommand;
        break;

    default:
        ereport(ERROR,
                errcode(ERRCODE_FDW_OPTION_NAME_NOT_FOUND),
                errmsg("error in setting the insert callback function."));

        break;
    }
    flow->insertContext = AllocSetContextCreate(mtstate->ps.state->es_query_cxt, "insert iter tmp memory", ALLOCSET_DEFAULT_SIZES);
    server = getOneConnection(flow->foreigntableid);
    c = server->c;
    flow->c = c;
    rinfo->ri_FdwState = (void *)flow;
}

TupleTableSlot *
fdw_redislinkExecForeignInsert(EState *estate,
                               ResultRelInfo *rinfo,
                               TupleTableSlot *slot,
                               TupleTableSlot *planSlot)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    MemoryContext old_context;
    Datum datum;
    int natts = 0;
    char *key = NULL;
    char *val = NULL;
    char *ttl = NULL;
    char **commands;
    char *command;
    int iter = 0;
    fdw_insertCommandC *commandc;
    redisContext *c = NULL;
    fdw_redisInsertState *info = (fdw_redisInsertState *)rinfo->ri_FdwState;
    if (info->key_pos != -1)
    {
        natts++;
    }
    if (info->val_pos != -1)
    {
        natts++;
    }
    if (info->ttl_pos != -1)
    {
        natts++;
    }
    old_context = MemoryContextSwitchTo(info->insertContext);
    for (int i = 1; i <= natts; i++)
    {
        bool isNull = false;
        datum = slot_getattr(slot, i, &isNull);
        if (i == info->key_pos)
        {
            key = DatumGetCString(OidFunctionCall1(info->typoutput[i - 1], datum));
        }
        if (i == info->val_pos)
        {
            val = DatumGetCString(OidFunctionCall1(info->typoutput[i - 1], datum));
        }
        if (i == info->ttl_pos)
        {
            ttl = DatumGetCString(OidFunctionCall1(info->typoutput[i - 1], datum));
        }
    }
    commands = info->fdw_insertCommand(info, key, val, ttl);
    command = commands[iter];
    while (command != NULL)
    {
        c = info->c;
        commandc = (fdw_insertCommandC *)palloc0(sizeof(fdw_insertCommandC));
        commandc->c = c;
        commandc->command = command;
        if (info->commandQueue1 == NULL)
        {
            info->commandQueue1 = list_make1(commandc);
        }
        else
        {
            info->commandQueue1 = lappend(info->commandQueue1, (void *)commandc);
        }
        command = commands[++iter];
    }
    MemoryContextSwitchTo(old_context);
    return slot;
}

void fdw_redislinkEndForeignModify(EState *estate, ResultRelInfo *rinfo)
{
    //elog(INFO, "*** %s", __FUNCTION__);
    MemoryContext old_context;
    fdw_redisInsertState *flow = (fdw_redisInsertState *)rinfo->ri_FdwState;
    old_context = MemoryContextSwitchTo(flow->insertContext);
    fdw_redisInsertFlow(flow);
    MemoryContextSwitchTo(old_context);
}