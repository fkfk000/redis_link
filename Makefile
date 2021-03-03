
MODULE_big = redis_link
OBJS = redis_link.o

EXTENSION = redis_link
DATA = redis_link--1.0.sql

SHLIB_LINK += -lhiredis


PG_CPPFLAGS+= -DDO_DEBUG

PGXS := $(shell pg_config --pgxs)
include $(PGXS)