#ifndef _REQUESTS_
#define _REQUESTS_

char *compute_get_request   (const char *host,
                             const char *url,
                             const char *query_params,
                             const char *auth_token,
                             char **cookies,
                             int cookies_count);

char *compute_delete_request(const char *host,
                             const char *url,
                             const char *query_params,
                             const char *auth_token,
                             char **cookies,
                             int cookies_count);

char *compute_post_request  (const char *host,
                             const char *url,
                             const char *content_type,
                             char **body_data,
                             int body_fields,
                             const char *auth_token,
                             char **cookies,
                             int cookies_count);

char *compute_put_request   (const char *host,
                             const char *url,
                             const char *content_type,
                             char **body_data,
                             int body_fields,
                             const char *auth_token,
                             char **cookies,
                             int cookies_count);

#endif
