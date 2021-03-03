CREATE FUNCTION redis_link_handler()
  RETURNS fdw_handler
  AS 'MODULE_PATHNAME'
  LANGUAGE C STRICT;


CREATE FUNCTION redis_link_validator(text[], oid)
  RETURNS void
  AS 'MODULE_PATHNAME'
  LANGUAGE C STRICT;


  
CREATE FOREIGN DATA WRAPPER redis_link
  HANDLER redis_link_handler
   VALIDATOR redis_link_validator;