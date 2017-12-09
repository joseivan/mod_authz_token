#include <string.h>
#include <stdlib.h>

#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_auth.h"

#define LOG_TAG "[mod_authz_token] "

#if MOD_AUTHZ_TOKEN_DEBUG
#define mod_rdebug(data, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, data, fmt, __VA_ARGS__)
#else
#define mod_rdebug(data, fmt, ...) do { ;; } while(0)
#endif

typedef struct {
    const char* token;
    const char* query_param;
} mod_authz_token_conf_t;


module AP_MODULE_DECLARE_DATA authz_token_module;

static const command_rec authz_token_cmds[] = {
        AP_INIT_TAKE1("Auth_token", ap_set_string_slot, (void*) APR_OFFSETOF(mod_authz_token_conf_t, token),
        OR_AUTHCFG, "Token to be used in verification"),
        AP_INIT_TAKE1("Auth_query_param", ap_set_string_slot, (void*) APR_OFFSETOF(mod_authz_token_conf_t, query_param),
        OR_AUTHCFG, "Query param used to read token value"),
        {NULL}
};

static authz_status authz_token_checker(request_rec *r, const char *require_args, const void *parsed_require_args);

static const authz_provider authz_token_provider = {
                        &authz_token_checker,
                        NULL,
};

static void register_hooks(apr_pool_t *p) {
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, NULL, LOG_TAG "registering hooks");
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "token", 
                         AUTHZ_PROVIDER_VERSION,
                 &authz_token_provider,
                 AP_AUTH_INTERNAL_PER_CONF);
}

static authz_status authz_token_checker(request_rec *req, const char *require_args, const void *parsed_require_args) {
    const char* args = req->args;
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, LOG_TAG "Checking token");
    
    if (args) {
        size_t i_indx = 0;
        size_t token_name_len = 0;
        size_t token_value_len = 0;
        size_t args_len = strlen(args);
        mod_authz_token_conf_t* conf = ap_get_module_config(req->per_dir_config, &authz_token_module);

	if (!conf || !(conf->token) || (!conf->query_param)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, LOG_TAG "Token or query param was not specified!");
            return AUTHZ_GENERAL_ERROR;
        }
	token_value_len = strlen(conf->token);
	token_name_len = strlen(conf->query_param);

#if MOD_AUTHZ_TOKEN_DEBUG
        char* d_token_var = malloc(token_name_len + 1);
	char* d_token_val = malloc(token_value_len + 1);
        d_token_var[token_name_len] = '\0';
	d_token_val[token_value_len] = '\0';
#endif

        while (i_indx < args_len) {
            // We should find a '=' just after token
            size_t eq_indx = i_indx + token_name_len;
            size_t q_div = i_indx;
            while (q_div < args_len && args[q_div] != '&') {
                q_div++;
            }
            
	    if (q_div >= args_len) {
                q_div = args_len;
            }

	    if (i_indx + token_name_len > args_len) {
                break;
	    }

#if MOD_AUTHZ_TOKEN_DEBUG
            strncpy(d_token_var, args + i_indx, token_name_len);
            mod_rdebug(req, "Request query var: '%s' fount at [%lu, %lu] %lu", d_token_var, i_indx, eq_indx, (eq_indx - i_indx));
#endif

            if (eq_indx < args_len && args[eq_indx] == '=' && !strncmp(conf->query_param, args + i_indx, token_name_len)) {
                // Let's verify token value
                // Make sure we have enough space to token value
                size_t v_indx = eq_indx + 1;
#if MOD_AUTHZ_TOKEN_DEBUG
                strncpy(d_token_val, args + v_indx, token_value_len);
                mod_rdebug(req, "Request query val: '%s' found at [%lu, %lu] %lu", d_token_val, v_indx, q_div, (q_div - v_indx));
#endif
		// Verify if given token has same test token length
                if ((q_div - v_indx) == token_value_len && v_indx + token_value_len <= args_len
                        && !strncmp(conf->token, args + v_indx, token_value_len)) {
#if MOD_AUTHZ_TOKEN_DEBUG
                    free(d_token_val);
                    free(d_token_var);
#endif
                    return AUTHZ_GRANTED;
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, LOG_TAG "Invalid token value");
                    // Only search for first token appearance
#if MOD_AUTHZ_TOKEN_DEBUG
                    free(d_token_val);
                    free(d_token_var);
#endif
		    return AUTHZ_DENIED;
                }
            }
            i_indx = q_div + 1;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, LOG_TAG "Token variable not found");
#if MOD_AUTHZ_TOKEN_DEBUG
	free(d_token_val);
	free(d_token_var);
#endif
    }

    return AUTHZ_DENIED;
}


static void *authz_token_dir_config(apr_pool_t *p, char *d) {
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, NULL, LOG_TAG "Directory config");

    mod_authz_token_conf_t *conf = (mod_authz_token_conf_t*) apr_palloc(p, sizeof(*conf));
    conf->token = NULL;
    conf->query_param = NULL;

    return conf;
}

module AP_MODULE_DECLARE_DATA   authz_token_module =
{
    STANDARD20_MODULE_STUFF,
    authz_token_dir_config, /* Per-directory configuration handler */
    NULL,  /* Merge handler for per-directory configurations */
    NULL, /* Per-server configuration handler */
    NULL,  /* Merge handler for per-server configurations */
    authz_token_cmds,      /* Any directives we may have for httpd */
    register_hooks   /* Our hook registering function */
};
