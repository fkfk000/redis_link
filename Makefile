MODULE_big = redis_link
OBJS = $(WIN32RES)  redis_link.o 

EXTENSION = redis_link
DATA = redis_link--1.0.sql

SHLIB_LINK += -lhiredis


PG_CPPFLAGS+= -DDO_DEBUG


ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/redis_link
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif