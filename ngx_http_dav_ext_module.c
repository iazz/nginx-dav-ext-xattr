/************************************************************************
  Copyright (c) 2012-2017, Roman Arutyunyan (arutyunyan.roman@gmail.com)
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ************************************************************************/

/*
 *
 * NGINX missing WebDAV commands support
 *
 * *PROPFIND & OPTIONS*
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/types.h>
#include <attr/xattr.h>
#include <dirent.h>
#include <time.h>
#include <stdlib.h>

#include <glib.h>

#include <expat.h>
#include <assert.h>

#define NGX_HTTP_DAV_EXT_OFF	2

/* Type of a configured regexp filter. */
typedef struct {
  ngx_regex_compile_t	regexp;
  u_char		errstr[NGX_MAX_CONF_ERRSTR];
} ngx_http_dav_ext_regexp_filter_t;

/* Type of variable that holds configuration directive values. */
typedef struct {
  ngx_uint_t				methods;
#if (NGX_PCRE)
  ngx_http_dav_ext_regexp_filter_t	getxattr_filter;
#endif /* (NGX_PCRE) */
} ngx_http_dav_ext_loc_conf_t;

/*
 * Function predeclarations required for the module configuration.
 */
static ngx_int_t
ngx_http_dav_ext_init(ngx_conf_t *cf);

static void *
ngx_http_dav_ext_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_dav_ext_merge_loc_conf(ngx_conf_t	*cf,
				void		*parent,
				void		*child);
#if (NGX_PCRE)
static char *
ngx_http_dav_ext_set_regexp_slot(ngx_conf_t	*cf,
				 ngx_command_t	*cmd,
				 void		*conf);
#endif /* (NGX_PCRE) */

/* Flags supported for the dav_ext_methods configuration directive. */
static ngx_conf_bitmask_t
ngx_http_dav_ext_methods_mask[] = {
  { ngx_string("off"),      NGX_HTTP_DAV_EXT_OFF },
  { ngx_string("propfind"), NGX_HTTP_PROPFIND    },
  { ngx_string("options"),  NGX_HTTP_OPTIONS     },
  { ngx_null_string,        0                    }
};

/* Configuration directives recognized by the module. */
static ngx_command_t
ngx_http_dav_ext_commands[] = {
  /* Supported WebDAV methods. */
  { ngx_string("dav_ext_methods"),
    NGX_HTTP_MAIN_CONF |
    NGX_HTTP_SRV_CONF  |
    NGX_HTTP_LOC_CONF  |
    NGX_CONF_1MORE,
    ngx_conf_set_bitmask_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_dav_ext_loc_conf_t, methods),
    &ngx_http_dav_ext_methods_mask },
#if (NGX_PCRE)
  /* Regexp to match the exposed xattr attributes. */
  { ngx_string("dav_ext_getxattr"),
    NGX_HTTP_MAIN_CONF |
    NGX_HTTP_SRV_CONF  |
    NGX_HTTP_LOC_CONF  |
    NGX_CONF_TAKE1,
    ngx_http_dav_ext_set_regexp_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_dav_ext_loc_conf_t, getxattr_filter),
    NULL },
#endif /* (NGX_PCRE) */
  ngx_null_command
};

/* Private module context. */
static ngx_http_module_t
ngx_http_dav_ext_module_ctx = {
  NULL,					/* Preconfiguration */
  ngx_http_dav_ext_init,		/* Postconfiguration */

  NULL,					/* Create main configuration */
  NULL,					/* Init main configuration */

  NULL,					/* Create server configuration */
  NULL,					/* Merge server configuration */

  ngx_http_dav_ext_create_loc_conf,	/* Create location configuration */
  ngx_http_dav_ext_merge_loc_conf,	/* Merge location configuration */
};

/* Module definition. */
ngx_module_t
ngx_http_dav_ext_module = {
  NGX_MODULE_V1,			/* Module private part */

  &ngx_http_dav_ext_module_ctx,		/* ctx:      Module context */
  ngx_http_dav_ext_commands,		/* commands: Module directives */
  NGX_HTTP_MODULE,			/* type:     Module type */

  NULL,					/* init_master */
  NULL,					/* init_module */
  NULL,					/* init_process */
  NULL,					/* init_thread */
  NULL,					/* exit_thread */
  NULL,					/* exit_process */
  NULL,					/* exit_master */
  NGX_MODULE_V1_PADDING
};

/* Flags used to mark XML nodes. */
#define NGX_HTTP_DAV_EXT_NODE_propfind           0x001
#define NGX_HTTP_DAV_EXT_NODE_prop               0x002
#define NGX_HTTP_DAV_EXT_NODE_propname           0x004
#define NGX_HTTP_DAV_EXT_NODE_allprop            0x008

/* Flags used to mark WebDAV properties. */
#define NGX_HTTP_DAV_EXT_PROP_creationdate       0x001
#define NGX_HTTP_DAV_EXT_PROP_displayname        0x002
#define NGX_HTTP_DAV_EXT_PROP_getcontentlanguage 0x004
#define	NGX_HTTP_DAV_EXT_PROP_getcontentlength   0x008
#define NGX_HTTP_DAV_EXT_PROP_getcontenttype     0x010
#define NGX_HTTP_DAV_EXT_PROP_getetag            0x020
#define NGX_HTTP_DAV_EXT_PROP_getlastmodified    0x040
#define NGX_HTTP_DAV_EXT_PROP_lockdiscovery      0x080
#define NGX_HTTP_DAV_EXT_PROP_resourcetype       0x100
#define NGX_HTTP_DAV_EXT_PROP_source             0x200
#define NGX_HTTP_DAV_EXT_PROP_supportedlock      0x400

/* Values telling which WebDAV properties to return. */
#define NGX_HTTP_DAV_EXT_PROPFIND_SELECTED       1
#define NGX_HTTP_DAV_EXT_PROPFIND_NAMES          2
#define NGX_HTTP_DAV_EXT_PROPFIND_ALL            3

/* The separator that Expat will use between XML namespace and element
   name.  It is not supposed to ever be used in a namespace name. */
#define NGX_HTTP_DAV_EXT_XML_NS_SEPARATOR	' '

/* The namespace used for WebDAV elements. */
#define NGX_HTTP_DAV_EXT_XML_NS_DAV		"DAV:"

/* The namespace used for xattr properties.  This will probably have
   to be changed if this code is to be accepted upstream. */
#define NGX_HTTP_DAV_EXT_XML_NS_XATTR		\
  "http://green-communications.fr/xattr/ns"

/* Type of an XML identifier. */
typedef struct {
  char	*namespace;
  char	*name;
} ngx_http_dav_ext_xml_id_t;

/* Type of an XML element attribute. */
typedef struct {
  ngx_http_dav_ext_xml_id_t	id;
  char				*value;
} ngx_http_dav_ext_xml_attr_t;

/* Type of an XML element, with attributes. */
typedef struct {
  ngx_http_dav_ext_xml_id_t	id;
  GQueue			attrs;
} ngx_http_dav_ext_xml_element_t;

/* Context for the XML parser callbacks. */
typedef struct {
  /* Table of all named properties in the propfind.
   * contains elements of type ngx_http_dav_ext_xml_element_t */
  GQueue	props;
  /* Which properties to return :
   * NGX_HTTP_DAV_EXT_PROPFIND_SELECTED: Return properties listed in props.
   * NGX_HTTP_DAV_EXT_PROPFIND_NAMES: Return the name of all properties.
   * NGX_HTTP_DAV_EXT_PROPFIND_ALL: Return all properties
   */
  ngx_uint_t	propfind;
  /* The current stack of XML elements in the current parser run.
   * contains elements of type ngx_http_dav_ext_xml_element_t */
  GQueue	elements;
  /* Whether parsing the XML has failed. */
  gboolean	failed;
} ngx_http_dav_ext_ctx_t;

/* Free memory allocated to an XML attribute. */
static void
ngx_http_dav_ext_xml_attr_free(gpointer p)
{
  ngx_http_dav_ext_xml_attr_t	*attr = p;
  if (attr != NULL) {
    free(attr->id.namespace);
    free(attr->id.name);
    free(attr->value);
    g_free(attr);
  }
}

/* Free memory allocated to an XML element. */
static void
ngx_http_dav_ext_xml_element_free(gpointer p)
{
  ngx_http_dav_ext_xml_element_t	*element = p;
  if (element != NULL) {
    free(element->id.namespace);
    free(element->id.name);
    g_queue_foreach(&element->attrs,
		    (GFunc) ngx_http_dav_ext_xml_attr_free, NULL);
    g_queue_clear(&element->attrs);
    g_free(element);
  }
}

/* Compare an XML id with a namespace and a name. */
static gboolean
ngx_http_dav_ext_xml_id_equal(const ngx_http_dav_ext_xml_id_t	*id,
				const char			*namespace,
				const char			*name)
{
  assert(namespace != NULL);
  assert(name != NULL);
  if (id == NULL)
    return FALSE;
  return strcmp(id->namespace, namespace) == 0 && strcmp(id->name, name) == 0;
}

/*
 * Convert an identifier's full name as provided by Expat, to an XML id.
 *
 * The id parameter can be set to the address of the id to set, or to
 * NULL if a new id has to be allocated.
 */
static ngx_http_dav_ext_xml_id_t *
ngx_http_dav_ext_xml_fullname_to_id(const char			*full_name,
				    ngx_http_dav_ext_xml_id_t	*id)
{
  if (full_name == NULL)
    return NULL;

  gboolean	locally_allocated = FALSE;
  if (id == NULL) {
    locally_allocated = TRUE;
    id                = g_try_malloc0(sizeof *id);
    if (id == NULL)
      return NULL;
  }

  const char	*space = strchr(full_name, NGX_HTTP_DAV_EXT_XML_NS_SEPARATOR);
  if (space == NULL){
    id->namespace = strdup("");
    id->name      = strdup(full_name);
  } else {
    id->namespace = strndup(full_name, space - full_name);
    id->name      = strdup(space + 1);
  }

  if (id->namespace != NULL && id->name != NULL)
    return id;

  free(id->namespace);
  free(id->name);
  if (locally_allocated)
    g_free(id);

  return NULL;
}


/*-----------------------------.
| XML Parser Element Callbacks |
`-----------------------------*/

/* XML parser callback for element start. */
static void
ngx_http_dav_ext_start_xml_elt(void		*user_data,
			       const XML_Char	*full_name,
			       const XML_Char	**attrs)
{
  ngx_http_dav_ext_ctx_t	*ctx  = user_data;
  assert(ctx != NULL);

  if (ctx->failed)
    return;

  ngx_http_dav_ext_xml_element_t	*element =
    g_try_malloc0(sizeof *element);

  if (element == NULL) {
    ctx->failed = TRUE;
    return;
  }

  g_queue_init(&element->attrs);

  if (ngx_http_dav_ext_xml_fullname_to_id(full_name, &element->id) == NULL)
    goto error;

  if (attrs != NULL) {
    size_t		i;

    for (i = 0; attrs[i] != NULL; i += 2) {
      ngx_http_dav_ext_xml_attr_t	*attr = g_try_malloc0(sizeof *attr);
      if (attr == NULL)
	break;
      if (ngx_http_dav_ext_xml_fullname_to_id(attrs[i], &attr->id) == NULL)
	goto fail;
      if (attrs[i + 1] != NULL) {
	attr->value = strdup(attrs[i + 1]);
	if (attr->value == NULL)
	  goto fail;
      }
      g_queue_push_tail(&element->attrs, attr);
      continue;
    fail:
      ngx_http_dav_ext_xml_attr_free(attr);
      break;
    }

    if (attrs[i] != NULL)
      goto error;
  }

  g_queue_push_tail(&ctx->elements, element);
  return;

error:
  ctx->failed = TRUE;
  ngx_http_dav_ext_xml_element_free(element);
}

/* XML parser callback for element end. */
static void
ngx_http_dav_ext_end_xml_elt(void		*user_data,
			     const XML_Char	*full_name)
{
  ngx_http_dav_ext_ctx_t	*ctx = user_data;

  if (ctx->failed)
    return;

  GList					*last_link;
  ngx_http_dav_ext_xml_element_t	*last;
  GList					*first_link;
  ngx_http_dav_ext_xml_element_t	*first;

  /* The the last limk. */
  last_link = g_queue_peek_tail_link(&ctx->elements);
  /* The queue of nodes cannot be empty. */
  if (last_link == NULL) {
    ctx->failed = TRUE;
    return;
  }

  /* Get the last started element. */
  last = last_link->data;
  assert(last != NULL);

  /* Check that the ending element is the last open one. */
  const char	*space = strchr(full_name, NGX_HTTP_DAV_EXT_XML_NS_SEPARATOR);
  if (space == NULL) {
    if (last->id.namespace[0] != 0 || strcmp(last->id.name, full_name) != 0) {
      ctx->failed = TRUE;
      return;
    }
  } else {
    if (strncmp(last->id.namespace, full_name, space - full_name) != 0 ||
	strcmp(last->id.name, space + 1) != 0) {
      ctx->failed = TRUE;
      return;
    }
  }

  /* Get the first link. */
  first_link = g_queue_peek_head_link(&ctx->elements);
  assert(first_link != NULL);

  /* Get the first started element. */
  first = first_link->data;

  do {
    if (ngx_http_dav_ext_xml_id_equal(&first->id,
				      NGX_HTTP_DAV_EXT_XML_NS_DAV,
				      "propfind")) {
      /* The first element is a propfind. */

      GList	*second_link = first_link->next;
      if (second_link != NULL) {
	ngx_http_dav_ext_xml_element_t	*second = second_link->data;

	if (strcmp(second->id.namespace, NGX_HTTP_DAV_EXT_XML_NS_DAV) == 0) {

	  if (strcmp(second->id.name, "prop") == 0) {
	    /* The second element is a prop. */

	    if (second_link->next == last_link) {
	      /* The third link is the last.  This is a property element. */

	      if (ctx->propfind &&
		  ctx->propfind != NGX_HTTP_DAV_EXT_PROPFIND_SELECTED)
		goto propfind_error;

	      ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_SELECTED;

	      /* Move the element to ctx->props and remove it from last_link. */
	      g_queue_push_tail(&ctx->props, last);
	      last_link->data = NULL;
	    }
	    break;
	  }

	  /* If there is not exactly two elements, stop. */
	  if (second_link != last_link)
	    break;

	  if (strcmp(second->id.name, "propname") == 0) {

	    if (ctx->propfind)
	      goto propfind_error;

	    ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_NAMES;
	    break;
	  }

	  if (strcmp(second->id.name, "allprop") == 0) {

	    if (ctx->propfind)
	      goto propfind_error;

	    ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_ALL;
	  }
	}
      }
      break;

    propfind_error:
      /* This happens when two conflicting elements appear in the same
	 propfind. */
      ctx->failed = TRUE;
    }
  } while (0);

  /* Pop the last element from the queue. */
  last_link = g_queue_pop_tail_link(&ctx->elements);
  if (last_link->data != NULL) {
    ngx_http_dav_ext_xml_element_free(last);
    last_link->data = NULL;
  }
  g_list_free(last_link);
}

#define NGX_HTTP_DAV_EXT_COPY    0x01
#define NGX_HTTP_DAV_EXT_ESCAPE  0x02

/* Add some data to the output chain. */
static void
ngx_http_dav_ext_output(ngx_http_request_t	*r,
			ngx_chain_t		**ll,
			ngx_int_t		flags,
			u_char			*data,
			ngx_uint_t		len)
{
  ngx_chain_t	*cl;
  ngx_buf_t	*b;

  if (!len)
    return;

  if (flags & NGX_HTTP_DAV_EXT_ESCAPE) {
    b       = ngx_create_temp_buf(r->pool,
				  len + ngx_escape_html(NULL, data, len));
    b->last = (u_char *) ngx_escape_html(b->pos, data, len);
  } else if (flags & NGX_HTTP_DAV_EXT_COPY) {
    b       = ngx_create_temp_buf(r->pool, len);
    b->last = ngx_cpymem(b->pos, data, len);
  } else {
    b         = ngx_calloc_buf(r->pool);
    b->memory = 1;
    b->pos    = data;
    b->start  = data;
    b->last   = b->pos + len;
    b->end    = b->last;
  }

  cl       = ngx_alloc_chain_link(r->pool);
  cl->buf  = b;
  cl->next = NULL;

  if (*ll != NULL) {
    cl->next    = (*ll)->next;
    (*ll)->next = cl;
    *ll         = cl;
  } else {
    *ll = cl;
    cl->next = cl;
  }
}

/* Send the output chain. */
static void
ngx_http_dav_ext_flush(ngx_http_request_t	*r,
		       ngx_chain_t		**ll)
{
  ngx_chain_t *cl = (*ll)->next;
  (*ll)->next = NULL;
  ngx_http_output_filter(r, cl);
  *ll = NULL;
}

/*
 * Output Shortcuts.
 *
 * These assume that the r variable (request pointer) exists in the
 * current context.  The _P version takes an explicit chain ptr ptr as
 * first argument, whereas the other doesn't and uses ll which is also
 * assumed to exist in the current context.
 *
 * Output chains are buffered in circular list & flushed on demand.
 */

/* Output buffer copy */
#define NGX_HTTP_DAV_EXT_OUTCB_P(ptr, data, len)			\
  ngx_http_dav_ext_output(r, (ptr), NGX_HTTP_DAV_EXT_COPY, (data), (len))
#define NGX_HTTP_DAV_EXT_OUTCB(data, len)				\
  NGX_HTTP_DAV_EXT_OUTCB_P(ll, (data), (len))

/* Output string (no copy) */
#define NGX_HTTP_DAV_EXT_OUTS_P(ptr, s)				\
  ngx_http_dav_ext_output(r, (ptr), 0, (s)->data, (s)->len)
#define NGX_HTTP_DAV_EXT_OUTS(s)	NGX_HTTP_DAV_EXT_OUTS_P(ll, (s))

/* Output escaped string */
#define NGX_HTTP_DAV_EXT_OUTES_P(ptr, s)				\
  ngx_http_dav_ext_output(r, (ptr), NGX_HTTP_DAV_EXT_ESCAPE,		\
			  (s)->data, (s)->len)
#define NGX_HTTP_DAV_EXT_OUTES(s)	NGX_HTTP_DAV_EXT_OUTES_P(ll, (s))

/* Output escaped data */
#define NGX_HTTP_DAV_EXT_OUTEB_P(ptr, data, len)			\
  ngx_http_dav_ext_output(r, (ptr), NGX_HTTP_DAV_EXT_ESCAPE, (data), (len))
#define NGX_HTTP_DAV_EXT_OUTEB(data, len)	\
  NGX_HTTP_DAV_EXT_OUTEB_P(ll, (data), (len))

/* Output literal */
#define NGX_HTTP_DAV_EXT_OUTL_P(ptr, s)					\
  ngx_http_dav_ext_output(r, (ptr), 0, (u_char *)(s), sizeof (s) - 1)
#define NGX_HTTP_DAV_EXT_OUTL(s)	NGX_HTTP_DAV_EXT_OUTL_P(ll, (s))

/* Type of an XML prefix allocator. */
typedef struct {
  /* Hash table mapping namespaces to prefixes. */
  GHashTable	*namespace_table;
  /* Pointer to the last allocated prefix. */
  const char	*last_prefix;
} ngx_http_dav_ext_xml_prefix_allocator_t;

/* Construct a new XML prefix allocator. */
static ngx_http_dav_ext_xml_prefix_allocator_t *
ngx_http_dav_ext_xml_prefix_allocator_new()
{
  ngx_http_dav_ext_xml_prefix_allocator_t	*p = g_try_malloc0(sizeof *p);
  if (p == NULL)
    return NULL;
  p->namespace_table = g_hash_table_new_full(g_str_hash, g_str_equal,
					     g_free, free);
  if (p->namespace_table == NULL) {
    g_free(p);
    return NULL;
  }
  return p;
}

/* Destroy an XML prefix allocator. */
static void
ngx_http_dav_ext_xml_prefix_allocator_free
(ngx_http_dav_ext_xml_prefix_allocator_t *allocator)
{
  if (allocator == NULL)
    return;
  g_hash_table_destroy(allocator->namespace_table);
  g_free(allocator);
}

/* Allocate a new prefix. */
static const char*
ngx_http_dav_ext_xml_namespace_to_prefix
(ngx_http_dav_ext_xml_prefix_allocator_t*	allocator,
 const char					*namespace)
{
  if (allocator == NULL)
    return NULL;
  const char	*value = g_hash_table_lookup(allocator->namespace_table,
					     namespace);
  if (value != NULL)
    return value;
  char	*namespace_copy = strdup(namespace);
  if (namespace_copy == NULL)
    return NULL;
  char	*new_prefix;
  /* Namespace not found. */
  if (allocator->last_prefix == NULL) {
    /* No last prefix, initialize to "A". */
    new_prefix = strdup("a");
    if (new_prefix == NULL)
      return NULL;
  } else {
    /* A last prefix exists, compute the following in lexicographical order. */
    new_prefix = strdup(allocator->last_prefix);
    if (new_prefix == NULL)
      return NULL;
    do {
      size_t	i;
      size_t	len = strlen(new_prefix);
      for (i = len; i != 0; --i) {
	if (new_prefix[i - 1] != 'z') {
	  ++new_prefix[i - 1];
	  break;
	}
	new_prefix[i - 1] = 'a';
      }
      if (i == 0 && new_prefix[0] == 'a') {
	char	*new_prefix_larger = realloc(new_prefix, len + 2);
	if (new_prefix_larger == NULL) {
	  free(new_prefix);
	  return NULL;
	}
	new_prefix = new_prefix_larger;
	strcat(new_prefix, "a");
      }
      /* Don't allow the allocated prefix to be "xmlns".
	 FIXME: There are probably others that should be excluded too. */
    } while (strcmp(new_prefix, "xmlns") == 0);
  }
  g_hash_table_insert(allocator->namespace_table, namespace_copy, new_prefix);
  allocator->last_prefix = new_prefix;
  return allocator->last_prefix;
}

/* Dump the requested xattr property of path.  Return
   NGX_HTTP_NOT_FOUND if either name->data is NULL or the property is
   not found. */
static ngx_int_t
ngx_http_dav_ext_send_propfind_xattr(ngx_http_request_t	*r,
				     char		*path,
				     ngx_chain_t	**ll,
				     ngx_http_dav_ext_xml_prefix_allocator_t
							*prefix_allocator,
				     const ngx_str_t	*name)
{
  ngx_http_dav_ext_loc_conf_t  *delcf =
    ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

  size_t			value_buffer_len;
  void				*value_buffer = NULL;

  if (name->data == NULL)
    goto not_found;

#if (NGX_PCRE)
  if (delcf->getxattr_filter.regexp.regex) {
    if (ngx_regex_exec(delcf->getxattr_filter.regexp.regex, name, NULL, 0) < 0)
      goto not_found;
  }
#endif /* (NGX_PCRE) */

  /* Retrieve the size of the xattr. */
  ssize_t	ret = getxattr(path, (const char *) name->data, NULL, 0);
  if (ret == -1) {
    if (errno == ENOATTR)
      goto not_found;
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  /* Retrieve the value of the xattr, by allocating a buffer of
     the right size. */
  do {
    value_buffer_len = (size_t) ret;
    void		*new_buffer = ngx_palloc(r->pool, value_buffer_len);
    if (new_buffer == NULL)
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (value_buffer)
      ngx_pfree(r->pool, value_buffer);
    value_buffer = new_buffer;
    ret = getxattr(path, (const char *) name->data,
		   value_buffer, value_buffer_len);
  } while (ret == -1 && errno == ERANGE);
  if (ret == -1) {
    if (errno == ENOATTR)
      goto not_found;
  }

  /* Possibly shrink the buffer size. */
  value_buffer_len = (size_t) ret;

  /* Check whether the buffer contains only printable characters. */
  const char	*p;
  gboolean	printable = TRUE;
  for (p = value_buffer;
       (size_t)(p - (const char *) value_buffer) < value_buffer_len; ++p)
    /* Printable characters would be those supported by XML (as
       per section 2.2 of REC-xml-20081126) excluding those
       larger than #x7f because they occupy more than one byte
       in UTF-8 and excluding #x7e (DEL) as well, since that
       would obviously not be readable. */
    if (*p != '\t' && *p != '\n' && *p != '\r' &&
	(*p < ' ' || *p > '~')) {
      printable = FALSE;
      break;
    }

  /* Allocate a prefix for the namespace if necessary. */
  const char	*prefix = ngx_http_dav_ext_xml_namespace_to_prefix
    (prefix_allocator, NGX_HTTP_DAV_EXT_XML_NS_XATTR);
  if (prefix == NULL)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;

  size_t		prefix_len = strlen(prefix);

  NGX_HTTP_DAV_EXT_OUTL("<");
  NGX_HTTP_DAV_EXT_OUTCB((u_char *) prefix, prefix_len);
  NGX_HTTP_DAV_EXT_OUTL(":getxattr ");
  NGX_HTTP_DAV_EXT_OUTCB((u_char *) prefix, prefix_len);
  NGX_HTTP_DAV_EXT_OUTL(":name=\"");
  NGX_HTTP_DAV_EXT_OUTES(name);
  NGX_HTTP_DAV_EXT_OUTL("\"");

  if (printable)
    NGX_HTTP_DAV_EXT_OUTL(" type=\"text/plain\">");
  else
    NGX_HTTP_DAV_EXT_OUTL(" type=\"application/base64\">");

  if (!printable) {
    /* The value has to be encoded in Base64. */
    size_t	base64_len     = (value_buffer_len / 3 + 2) * 4;
    char	*base64_buffer = ngx_palloc(r->pool, base64_len);
    if (base64_buffer == NULL)
      return NGX_HTTP_INTERNAL_SERVER_ERROR;

    gint		state = 0;
    gint		save  = 0;
    gsize		base64_bytes =
      g_base64_encode_step(value_buffer, value_buffer_len, FALSE,
			   base64_buffer, &state, &save);
    base64_bytes += g_base64_encode_close(FALSE,
					  base64_buffer + base64_bytes,
					  &state, &save);

    NGX_HTTP_DAV_EXT_OUTEB((u_char *) base64_buffer, base64_bytes);
    ngx_pfree(r->pool, base64_buffer);
  } else
    NGX_HTTP_DAV_EXT_OUTEB(value_buffer, value_buffer_len);

  NGX_HTTP_DAV_EXT_OUTL("</");
  NGX_HTTP_DAV_EXT_OUTCB((u_char *) prefix, prefix_len);
  NGX_HTTP_DAV_EXT_OUTL(":getxattr>\n");

  return NGX_OK;

not_found:
  if (value_buffer != NULL)
    ngx_pfree(r->pool, value_buffer);

  return NGX_HTTP_NOT_FOUND;
}

/* Add the requested properties to the output chain and any property
   that's not found to props_not_found for error reporting by the
   caller.  Prefixes are generated on-demand based on the
   namespace_table and last_prefix. */
static ngx_int_t
ngx_http_dav_ext_send_propfind_atts(ngx_http_request_t	*r,
				    char		*path,
				    ngx_str_t		*uri,
				    ngx_chain_t		**ll,
				    GQueue		*props_not_found,
				    ngx_http_dav_ext_xml_prefix_allocator_t
							*prefix_allocator)
{
  struct stat   st;
  struct tm     stm;
  u_char        buf[256];
  ngx_str_t     name;


  if (stat(path, &st)) {
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
		  "dav_ext stat failed on '%s'", path);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_http_dav_ext_ctx_t	*ctx =
    ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

  gboolean	dump_all = ctx->propfind == NGX_HTTP_DAV_EXT_PROPFIND_ALL;

  GList		*prop_link;

  /* Either iterate on all requested properties, or if dump_all is set,
   * iterate once and add all properties in one iteration. */
  for (prop_link = g_queue_peek_head_link(&ctx->props);
       prop_link != NULL || dump_all; prop_link = prop_link->next) {

    ngx_http_dav_ext_xml_element_t	*prop = dump_all? NULL: prop_link->data;

    /*
     * creationdate
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "creationdate")) {
      /* Output file ctime (attr change time) as creation time. */
      if (gmtime_r(&st.st_ctime, &stm) == NULL)
	return NGX_HTTP_INTERNAL_SERVER_ERROR;

      /* ISO 8601 time format 2012-02-20T16:15:00Z */
      NGX_HTTP_DAV_EXT_OUTCB(buf, strftime((char *) buf, sizeof(buf),
					   "<D:creationdate>"
					   "%Y-%m-%dT%TZ"
					   "</D:creationdate>\n",
					   &stm));
    }

    /*
     * displayname
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "displayname")) {

      NGX_HTTP_DAV_EXT_OUTL("<D:displayname>");

      if (uri->len) {
	for(name.data = uri->data + uri->len;
	    name.data >= uri->data + 1 && name.data[-1] != '/';
	    --name.data);

	name.len = uri->data + uri->len - name.data;

	NGX_HTTP_DAV_EXT_OUTES(&name);
      }

      NGX_HTTP_DAV_EXT_OUTL("</D:displayname>\n");
    }

    /*
     * getcontentlanguage
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "getcontentlanguage"))
      NGX_HTTP_DAV_EXT_OUTL("<D:getcontentlanguage/>\n");

    /*
     * getcontentlength
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "getcontentlength"))
      NGX_HTTP_DAV_EXT_OUTCB(buf, ngx_snprintf(buf, sizeof(buf),
					       "<D:getcontentlength>"
					       "%O"
					       "</D:getcontentlength>\n",
					       st.st_size) - buf);

    /*
     * getcontenttype
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "getcontenttype"))
      NGX_HTTP_DAV_EXT_OUTL("<D:getcontenttype/>\n");

    /*
     * getetag
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "getetag"))
      NGX_HTTP_DAV_EXT_OUTL("<D:getetag/>\n");

    /*
     * getlastmodified
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "getlastmodified")) {

      if (gmtime_r(&st.st_mtime, &stm) == NULL)
	return NGX_HTTP_INTERNAL_SERVER_ERROR;

      /* RFC 2822 time format */
      NGX_HTTP_DAV_EXT_OUTCB(buf, strftime((char*)buf, sizeof(buf),
					   "<D:getlastmodified>"
					   "%a, %d %b %Y %T GMT"
					   "</D:getlastmodified>\n",
					   &stm));
    }

    /*
     * lockdiscovery
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "lockdiscovery"))
      NGX_HTTP_DAV_EXT_OUTL("<D:lockdiscovery/>\n");

    /*
     * resourcetype
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "resourcetype")) {
      if (S_ISDIR(st.st_mode))
	NGX_HTTP_DAV_EXT_OUTL("<D:resourcetype>"
			      "<D:collection/>"
			      "</D:resourcetype>\n");
      else
	NGX_HTTP_DAV_EXT_OUTL("<D:resourcetype/>\n");
    }

    /*
     * source
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "source"))
      NGX_HTTP_DAV_EXT_OUTL("<D:source/>\n");

    /*
     * supportedlock
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_DAV,
						  "supportedlock"))
      NGX_HTTP_DAV_EXT_OUTL("<D:supportedlock/>\n");

    /*
     * getxattr
     */
    if (dump_all || ngx_http_dav_ext_xml_id_equal(&prop->id,
						  NGX_HTTP_DAV_EXT_XML_NS_XATTR,
						  "getxattr")) {
      size_t	name_buffer_len;
      char	*name_buffer = NULL;

      if (dump_all) {
	/* Retrieve the list of attribute names. */
	ssize_t	ret = listxattr(path, NULL, 0);
	if (ret == -1) {
	  ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
			"dav_ext error getting list of extended attributes");
	  return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	/* Allocate a buffer of the right size. */
	do {
	  name_buffer_len = (size_t) ret;
	  char	*new_buffer = ngx_palloc(r->pool, name_buffer_len);
	  if (new_buffer == NULL)
	    return NGX_HTTP_INTERNAL_SERVER_ERROR;
	  if (name_buffer != NULL)
	    ngx_pfree(r->pool, name_buffer);
	  name_buffer = new_buffer;
	  ret = listxattr(path, name_buffer, name_buffer_len);
	} while (ret == -1 && errno == ERANGE);
	if (ret == -1) {
	  ngx_log_error(NGX_LOG_ERR, r->connection->log, errno,
			"dav_ext error getting list of extended attributes");
	  return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	name_buffer_len = (size_t) ret;
	/* Check that the name buffer is null-terminated. */
	if (name_buffer[name_buffer_len - 1] != 0) {
	  ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
			"dav_ext list of extended attributes names is not"
			" null-terminated");
	  return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	/* Iterate over the attribute names. */
	ngx_str_t	name = ngx_null_string;
	for (name.len = strnlen(name_buffer, name_buffer_len),
	       name.data = (u_char *) name_buffer;
	     name.data < (u_char *) name_buffer + name_buffer_len;
	     name.data += name.len + 1,
	       name.len = strnlen((const char *) name.data,
				  name_buffer_len
				  - (size_t)(name.data
					     - (u_char *) name_buffer))) {
	  /* Try to dump the attribute value. */
	  ngx_uint_t	code =
	    ngx_http_dav_ext_send_propfind_xattr(r, path, ll,
						 prefix_allocator, &name);
	  switch (code) {
	  case NGX_OK:
	  case NGX_HTTP_NOT_FOUND:
	    /* Whether the attribute was there or not makes no
	       difference since we're in a allprop dump. */
	    break;
	  default:
	    return code;
	  }
	}
      } else { /* !dump_all */
	/* Look for the name attribute. */
	ngx_str_t	name = ngx_null_string;
	GList		*attr_link;
	for (attr_link = g_queue_peek_head_link(&prop->attrs);
	     attr_link != NULL; attr_link = attr_link->next) {
	  ngx_http_dav_ext_xml_attr_t	*attr = attr_link->data;
	  assert(attr != NULL);
	  if (ngx_http_dav_ext_xml_id_equal(&attr->id,
					    NGX_HTTP_DAV_EXT_XML_NS_XATTR,
					    "name")) {
	    name.data = (u_char *) attr->value;
	    name.len  = strlen(attr->value);
	    break;
	  }
	}

	ngx_uint_t	code =
	  ngx_http_dav_ext_send_propfind_xattr(r, path, ll,
					       prefix_allocator, &name);

	switch (code) {
	case NGX_OK:
	  break;
	case NGX_HTTP_NOT_FOUND:
	  {
	    /* Add a reference to the requested property to props_not_found
	     * and continue with the next property. */
	    g_queue_push_tail(props_not_found, prop);
	    continue;
	  }
	default:
	  return code;
	}
      }
    }

    /* Stop here if dumping all, we don't want to touch prop_link. */
    if (dump_all)
      break;
  }

  return NGX_OK;
}

/* Send the propfind element and its content to the output. */
static ngx_int_t
ngx_http_dav_ext_send_propfind_item(ngx_http_request_t	*r,
				    char		*path,
				    ngx_str_t		*uri)
{
  ngx_http_dav_ext_ctx_t *ctx;
  ngx_chain_t            *l = NULL, **ll = &l;
  u_char                 vbuf[8];
  ngx_str_t              status_line = ngx_string("200 OK");

  ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

  NGX_HTTP_DAV_EXT_OUTL("<D:response");

  /* The pointer to the node in the chain that will allow to add the
     namespace definitions to the response element later. */
  ngx_chain_t		*ns_insert_ll = *ll;

  NGX_HTTP_DAV_EXT_OUTL(">\n"
			"<D:href>");

  NGX_HTTP_DAV_EXT_OUTES(uri);

  NGX_HTTP_DAV_EXT_OUTL("</D:href>\n"
			"<D:propstat>\n"
			"<D:prop>\n");

  /* The queue of properties that could not be found, kept to be
     embedded in a separate propstat indicating this error. */
  GQueue	props_not_found;
  g_queue_init(&props_not_found);

  /* The prefix allocator to be used if required. */
  ngx_http_dav_ext_xml_prefix_allocator_t	*prefix_allocator =
    ngx_http_dav_ext_xml_prefix_allocator_new();

  if (ctx->propfind == NGX_HTTP_DAV_EXT_PROPFIND_NAMES) {
    NGX_HTTP_DAV_EXT_OUTL("<D:creationdate/>\n"
			  "<D:displayname/>\n"
			  "<D:getcontentlanguage/>\n"
			  "<D:getcontentlength/>\n"
			  "<D:getcontenttype/>\n"
			  "<D:getetag/>\n"
			  "<D:getlastmodified/>\n"
			  "<D:lockdiscovery/>\n"
			  "<D:resourcetype/>\n"
			  "<D:source/>\n"
			  "<D:supportedlock/>\n");
    /* Retrieve the size of the list of xattr for that path. */
    ssize_t	ret = listxattr(path, NULL, 0);
    if (ret != -1) {
      /* Allocate a buffer of the right size. */
      size_t	buffer_len;
      char	*buffer = NULL;
      do {
	buffer_len = (size_t) ret;
	char	*new_buffer = realloc(buffer, buffer_len);
	if (new_buffer == NULL)
	  goto skip_list_xattr_props;
	buffer = new_buffer;
	ret = listxattr(path, buffer, buffer_len);
      } while (ret == -1 && errno == ERANGE);
      if (ret != -1) {
	/* Retrieve the configuration for the location. */
	ngx_http_dav_ext_loc_conf_t  *delcf
	  = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

	buffer_len = (size_t) ret;
	char		*p;
	const char	*prefix    = NULL;
	size_t		prefix_len = 0;
	for (p = buffer; (size_t)(p - buffer) < buffer_len;
	     p += strlen(p) + 1) {
#if (NGX_PCRE)
	  /* Check that the xattr name matches the configured allowed
	     regexp. */
	  if (delcf->getxattr_filter.regexp.regex) {
	    ngx_str_t	input = { strnlen(p, buffer_len - (size_t)(p - buffer)),
				  (u_char *) p };
	    if (ngx_regex_exec(delcf->getxattr_filter.regexp.regex,
			       &input, NULL, 0) < 0)
	      continue;
	  }
#endif /* (NGX_PCRE) */
	  if (prefix == NULL) {
	    /* Get a prefix for that namespace if not already allocated. */
	    prefix = ngx_http_dav_ext_xml_namespace_to_prefix
	      (prefix_allocator, NGX_HTTP_DAV_EXT_XML_NS_XATTR);
	    if (prefix == NULL)
	      goto skip_list_xattr_props;
	    prefix_len = strlen(prefix);
	  }
	  NGX_HTTP_DAV_EXT_OUTL("<");
	  NGX_HTTP_DAV_EXT_OUTCB((u_char *) prefix, prefix_len);
	  NGX_HTTP_DAV_EXT_OUTL(":getxattr ");
	  NGX_HTTP_DAV_EXT_OUTCB((u_char *) prefix, prefix_len);
	  NGX_HTTP_DAV_EXT_OUTL(":name=\"");
	  NGX_HTTP_DAV_EXT_OUTEB((u_char *) p,
				 strnlen(p, buffer_len - (size_t)(p - buffer)));
	  NGX_HTTP_DAV_EXT_OUTL("\"/>\n");
	}
      }
    skip_list_xattr_props:
      free(buffer);
    }
  } else {
    /* Process each selected property or all of them, depending on
       ctx->propfind. */
    ngx_int_t	code = ngx_http_dav_ext_send_propfind_atts(r, path, uri, ll,
							   &props_not_found,
							   prefix_allocator);
    if (code != NGX_OK) {
      /* This currently doesn't support other HTTP error codes.  Nginx
	 doesn't export any function to generate a status line based
	 on the code, so they have to be processed individually here.
	 If other errors are to be supported, add the code here. */
      switch (code) {
      case NGX_HTTP_BAD_REQUEST:
	ngx_str_set(&status_line, "400 Bad Request");
	break;
      default:
	ngx_str_set(&status_line, "500 Internal Server Error");
	break;
      }
      g_queue_clear(&props_not_found);
    }
  }

  NGX_HTTP_DAV_EXT_OUTL("</D:prop>\n"
			"<D:status>HTTP/");

  NGX_HTTP_DAV_EXT_OUTCB(vbuf, ngx_snprintf(vbuf, sizeof(vbuf), "%d.%d ",
					    r->http_major, r->http_minor)
			 - vbuf);

  NGX_HTTP_DAV_EXT_OUTS(&status_line);

  NGX_HTTP_DAV_EXT_OUTL("</D:status>\n"
			"</D:propstat>\n");

  /* Process the queue of properties that could not be found. */
  if (!g_queue_is_empty(&props_not_found)) {
    NGX_HTTP_DAV_EXT_OUTL("<D:propstat>\n"
			  "<D:prop>\n");

    /* Iterate on the queue. */
    GList	*prop_link;
    while ((prop_link = g_queue_pop_head_link(&props_not_found)) != NULL) {
      ngx_http_dav_ext_xml_element_t	*prop = prop_link->data;
      assert(prop != NULL);

      NGX_HTTP_DAV_EXT_OUTL("<");
      if (prop->id.namespace[0] != '\0') {
	if (g_strcmp0(prop->id.namespace,
		      NGX_HTTP_DAV_EXT_XML_NS_DAV) == 0)
	  NGX_HTTP_DAV_EXT_OUTL("D:");
	else {
	  /* Allocate a prefix for that namespace if necessary. */
	  const char	*prefix = ngx_http_dav_ext_xml_namespace_to_prefix
	    (prefix_allocator, prop->id.namespace);
	  if (prefix == NULL)
	    goto skip;
	  NGX_HTTP_DAV_EXT_OUTCB((u_char *) prefix, strlen(prefix));
	  NGX_HTTP_DAV_EXT_OUTL(":");
	}
      }
      NGX_HTTP_DAV_EXT_OUTCB((u_char *) prop->id.name,
			     strlen(prop->id.name));
      GList	*attr_link;
      for (attr_link = g_queue_peek_head_link(&prop->attrs);
	   attr_link; attr_link = attr_link->next) {
	const ngx_http_dav_ext_xml_attr_t	*attr = attr_link->data;
	assert(attr != NULL);
	NGX_HTTP_DAV_EXT_OUTL(" ");
	if (attr->id.namespace[0] != '\0') {
	  if (g_strcmp0(attr->id.namespace, NGX_HTTP_DAV_EXT_XML_NS_DAV) == 0)
	    NGX_HTTP_DAV_EXT_OUTL("D:");
	  else {
	    /* Allocate a prefix for this namespace if necessary. */
	    const char	*prefix = ngx_http_dav_ext_xml_namespace_to_prefix
	      (prefix_allocator, attr->id.namespace);
	    if (prefix == NULL)
	      goto skip;
	    NGX_HTTP_DAV_EXT_OUTCB((u_char *) prefix, strlen(prefix));
	    NGX_HTTP_DAV_EXT_OUTL(":");
	  }
	}
	NGX_HTTP_DAV_EXT_OUTCB((u_char *) attr->id.name, strlen(attr->id.name));
	NGX_HTTP_DAV_EXT_OUTL("=\"");
	NGX_HTTP_DAV_EXT_OUTEB((u_char *) attr->value, strlen(attr->value));
	NGX_HTTP_DAV_EXT_OUTL("\"");
      }
      NGX_HTTP_DAV_EXT_OUTL("/>\n");
    skip:
      g_list_free(prop_link);
    }

    NGX_HTTP_DAV_EXT_OUTL("</D:prop>\n"
			  "<D:status>HTTP/");
    NGX_HTTP_DAV_EXT_OUTCB(vbuf, ngx_snprintf(vbuf, sizeof(vbuf), "%d.%d ",
					      r->http_major, r->http_minor)
			   - vbuf);
    NGX_HTTP_DAV_EXT_OUTL("404 Not Found</D:status>\n"
			  "</D:propstat>\n");
  }

  /* Iterate over the allocated prefixes and insert namespace
     definitions to the response node. */
  {
    GHashTableIter	iter;
    char		*key, *value;
    g_hash_table_iter_init(&iter, prefix_allocator->namespace_table);
    while (g_hash_table_iter_next(&iter,
				  (gpointer *) &key,
				  (gpointer *) &value)) {
      NGX_HTTP_DAV_EXT_OUTL_P(&ns_insert_ll, " xmlns:");
      NGX_HTTP_DAV_EXT_OUTCB_P(&ns_insert_ll, (u_char *) value, strlen(value));
      NGX_HTTP_DAV_EXT_OUTL_P(&ns_insert_ll, "=\"");
      NGX_HTTP_DAV_EXT_OUTEB_P(&ns_insert_ll, (u_char *) key, strlen(key));
      NGX_HTTP_DAV_EXT_OUTL_P(&ns_insert_ll, "\"");
    }
    ngx_http_dav_ext_xml_prefix_allocator_free(prefix_allocator);
  }

  NGX_HTTP_DAV_EXT_OUTL("</D:response>\n");

  ngx_http_dav_ext_flush(r, ll);

  return NGX_OK;
}

/* Path returned by this function is terminated with a hidden
   (out-of-len) null. */
static void
ngx_http_dav_ext_make_child(ngx_pool_t	*pool,
			    ngx_str_t	*parent,
			    u_char	*child,
			    size_t	chlen,
			    ngx_str_t	*path)
{
  u_char	*s;

  path->data = ngx_palloc(pool, parent->len + 2 + chlen);
  s          = path->data;
  s          = ngx_cpymem(s, parent->data, parent->len);
  if (parent->len > 0 && s[-1] != '/')
    *s++ = '/';
  s         = ngx_cpymem(s, child, chlen);
  path->len = s - path->data;
  *s        = 0;
}

#define DAV_EXT_INFINITY (-1)

static ngx_int_t
ngx_http_dav_ext_send_propfind(ngx_http_request_t *r)
{
  size_t                    root;
  ngx_str_t                 path, spath, ruri, suri;
  ngx_chain_t               *l = NULL, **ll = &l;
  DIR                       *dir;
  int                       depth;
  struct dirent             *de;
  size_t                    len, uc_len;
  ngx_http_variable_value_t vv;
  ngx_str_t                 depth_name = ngx_string("depth");
  u_char                    *p, *uc;

  if (ngx_http_variable_unknown_header
      (&vv, &depth_name, &r->headers_in.headers.part, 0) != NGX_OK)
    return NGX_ERROR;

  if (!vv.not_found) {
    if (vv.len == sizeof ("infinity") -1 &&
	!ngx_strncasecmp(vv.data, (u_char *) "infinity", vv.len))
      depth = DAV_EXT_INFINITY;
    else
      depth = ngx_atoi(vv.data, vv.len);
  } else
    depth = DAV_EXT_INFINITY;

  p = ngx_http_map_uri_to_path(r, &path, &root, 0);

  if (p == NULL || !path.len) {
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
		  "dav_ext error mapping uri to path");
    return NGX_ERROR;
  }

  path.len = p - path.data;
  *p       = 0;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		 "http propfind path: \"%V\"", &path);

  NGX_HTTP_DAV_EXT_OUTL("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n"
			"<D:multistatus xmlns:D=\""
			NGX_HTTP_DAV_EXT_XML_NS_DAV "\">\n");

  ngx_http_dav_ext_flush(r, ll);

  /* ruri.data = ngx_palloc(r->pool, r->uri.len + 2 * ngx_escape_uri(NULL, */
  /* r->uri.data, r->uri.len, NGX_ESCAPE_URI)); */
  /* if (ruri.data == NULL) */
  /*   return NGX_ERROR; */

  /* ruri.len = (u_char *) ngx_escape_uri(ruri.data, r->uri.data, r->uri.len, */
  /*				       NGX_ESCAPE_URI) - ruri.data; */

  ruri = r->unparsed_uri;

  ngx_http_dav_ext_send_propfind_item(r, (char *) path.data, &ruri);

  if (depth) {
    /* Treat infinite depth as 1 for performance reasons. */

    if ((dir = opendir((char *) path.data))) {

      while((de = readdir(dir))) {
	if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
	  continue;

	len = strlen(de->d_name);

	ngx_http_dav_ext_make_child(r->pool, &path, (u_char *) de->d_name,
				    len, &spath);

	/* Escape URI component. */

	uc = ngx_palloc(r->pool, len + 2 *
			ngx_escape_uri(NULL, (u_char *) de->d_name,
				       len, NGX_ESCAPE_URI_COMPONENT));
	if (uc == NULL)
	  return NGX_ERROR;

	uc_len = (u_char *) ngx_escape_uri(uc, (u_char *) de->d_name, len,
					   NGX_ESCAPE_URI_COMPONENT) - uc;

	ngx_http_dav_ext_make_child(r->pool, &ruri, uc, uc_len, &suri);

	ngx_http_dav_ext_send_propfind_item(r, (char *) spath.data, &suri);
      }

      closedir(dir);
    }

  }

  NGX_HTTP_DAV_EXT_OUTL("</D:multistatus>\n");

  if (*ll && (*ll)->buf)
    (*ll)->buf->last_buf = 1;

  ngx_http_dav_ext_flush(r, ll);

  return NGX_OK;
}

static void
ngx_http_dav_ext_propfind_handler(ngx_http_request_t *r)
{
  ngx_chain_t			*c;
  XML_Parser			parser;
  ngx_uint_t			status;
  ngx_http_dav_ext_ctx_t	*ctx = NULL;

  ctx = ngx_http_get_module_ctx(r, ngx_http_dav_ext_module);

  if (ctx == NULL) {
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dav_ext_ctx_t));
    if (ctx == NULL)
      goto error;
    g_queue_init(&ctx->props);
    g_queue_init(&ctx->elements);
    ctx->failed = FALSE;
    ngx_http_set_ctx(r, ctx, ngx_http_dav_ext_module);
  }

  status = NGX_OK;

  parser = XML_ParserCreateNS(NULL, ' ');

  XML_SetUserData(parser, ctx);

  XML_SetElementHandler(parser,
			ngx_http_dav_ext_start_xml_elt,
			ngx_http_dav_ext_end_xml_elt);

  gboolean	body_present = FALSE;

  for (c = r->request_body->bufs; c != NULL; c = c->next) {
    if (c->buf == NULL)
      continue;

    body_present = TRUE;

    ngx_buf_t	*b = c->buf;

    if (!XML_Parse(parser, (const char *) b->pos,
		   b->last - b->pos, b->last_buf) || ctx->failed) {
      ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
		    "dav_ext propfind XML error");
      status = NGX_ERROR;
      break;
    }
  }

  XML_ParserFree(parser);

  if (status == NGX_OK) {
    if (!body_present)
      /* No request XML provided, dump all properties. */
      ctx->propfind = NGX_HTTP_DAV_EXT_PROPFIND_ALL;
    r->headers_out.status = 207;
    ngx_str_set(&r->headers_out.status_line, "207 Multi-Status");
    /* Add application/xml header required by RFC 4918. */
    ngx_str_set(&r->headers_out.content_type, "application/xml");
    ngx_http_send_header(r);
    ngx_http_finalize_request(r, ngx_http_dav_ext_send_propfind(r));
  } else
    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

  if (ctx != NULL) {
    g_queue_foreach(&ctx->props,
		    (GFunc) ngx_http_dav_ext_xml_element_free, NULL);
    g_queue_clear(&ctx->props);
    g_queue_foreach(&ctx->elements,
		    (GFunc) ngx_http_dav_ext_xml_element_free, NULL);
    g_queue_clear(&ctx->elements);
    ctx->propfind = 0;
  }

  return;

error:
  ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
}

static ngx_int_t
ngx_http_dav_ext_handler(ngx_http_request_t *r)
{
  ngx_int_t                    rc;
  ngx_table_elt_t              *h;
  ngx_http_dav_ext_loc_conf_t  *delcf;

  delcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_ext_module);

  if (!(r->method & delcf->methods))
    return NGX_DECLINED;

  switch (r->method) {
  case NGX_HTTP_PROPFIND:
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		   "dav_ext propfind");

    rc = ngx_http_read_client_request_body(r,
					   ngx_http_dav_ext_propfind_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
      return rc;

    return NGX_DONE;

  case NGX_HTTP_OPTIONS:
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		   "dav_ext options");

    h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL)
      return NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_str_set(&h->key, "DAV");
    ngx_str_set(&h->value, "1");
    h->hash = 1;

    h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL)
      return NGX_HTTP_INTERNAL_SERVER_ERROR;

    /* FIXME: It looks so ugly because I cannot access nginx dav module. */
    ngx_str_set(&h->key, "Allow");
    ngx_str_set(&h->value, "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,"
		"PROPFIND,OPTIONS");
    h->hash = 1;

    r->headers_out.status           = NGX_HTTP_OK;
    r->header_only                  = 1;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);

    return NGX_OK;
  }

  return NGX_DECLINED;
}

static void *
ngx_http_dav_ext_create_loc_conf(ngx_conf_t *cf)
{
  ngx_http_dav_ext_loc_conf_t  *conf;

  conf = ngx_pcalloc(cf->pool, sizeof (ngx_http_dav_ext_loc_conf_t));

  if (conf == NULL)
    return NULL;

  return conf;
}

static char *
ngx_http_dav_ext_merge_loc_conf(ngx_conf_t	*cf,
				void		*parent,
				void		*child)
{
  ngx_http_dav_ext_loc_conf_t  *prev = parent;
  ngx_http_dav_ext_loc_conf_t  *conf = child;

  ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
			       NGX_CONF_BITMASK_SET | NGX_HTTP_DAV_EXT_OFF);

  return NGX_CONF_OK;
}

#if (NGX_PCRE)
/* Process a regexp configuration argument. */
static char *
ngx_http_dav_ext_set_regexp_slot(ngx_conf_t	*cf,
				 ngx_command_t	*cmd,
				 void		*conf)
{
  char	*p = conf;

  ngx_str_t				*value;
  ngx_http_dav_ext_regexp_filter_t	*field;
  ngx_conf_post_t			*post;

  field = (ngx_http_dav_ext_regexp_filter_t *)(p + cmd->offset);

  if (field->regexp.pattern.data)
    return "is duplicate";

  value = cf->args->elts;

  field->regexp.pattern  = value[1];
  field->regexp.pool     = cf->pool;
  field->regexp.err.len  = NGX_MAX_CONF_ERRSTR;
  field->regexp.err.data = field->errstr;

  if (ngx_regex_compile(&field->regexp) != NGX_OK) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &field->regexp.err);
    return NGX_CONF_ERROR;
  }

  if (cmd->post) {
    post = cmd->post;
    return post->post_handler(cf, post, field);
  }

  return NGX_CONF_OK;
}
#endif /* (NGX_PCRE) */

/*
 * Initialize module.
 */
static ngx_int_t
ngx_http_dav_ext_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);

  if (h == NULL)
    return NGX_ERROR;

  *h = ngx_http_dav_ext_handler;

  return NGX_OK;
}
