#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "helpers.h"
#include "requests.h"

static void add_cookies(char *msg, char **cookies, int n)
{
    if (!cookies || n <= 0)
        return;

    char line[LINELEN] = "Cookie: ";

    for (int i = 0; i < n; i++) {
        strcat(line, cookies[i]);
        if (i < n - 1)
            strcat(line, "; ");
    }

    compute_message(msg, line);
}

static void add_std_headers(char *msg,
                            const char *host,
                            const char *auth_token)
{
    char line[LINELEN];

    sprintf(line, "Host: %s", host);
    compute_message(msg, line);

    if (auth_token) {
        sprintf(line, "Authorization: Bearer %s", auth_token);
        compute_message(msg, line);
    }

    compute_message(msg, "Connection: close");
}

static char *simple_request(const char *verb,
                            const char *host,
                            const char *url,
                            const char *query,
                            const char *auth_token,
                            char **cookies, int nc)
{
    char *msg           = calloc(BUFLEN, 1);
    char  first_line[LINELEN];

    if (query && strlen(query) > 0) {
        sprintf(first_line, "%s %s?%s HTTP/1.1", verb, url, query);
    } else {
        sprintf(first_line, "%s %s HTTP/1.1",  verb, url);
    }

    compute_message(msg, first_line);
    add_std_headers(msg, host, auth_token);
    add_cookies(msg, cookies, nc);
    compute_message(msg, "");

    return msg;
}

char *compute_get_request(const char *host, const char *url, const char *query,
                          const char *auth_token,
                          char **cookies, int nc)
{
    return simple_request("GET", host, url, query, auth_token, cookies, nc);
}

char *compute_delete_request(const char *host, const char *url, const char *query,
                             const char *auth_token,
                             char **cookies, int nc)
{
    return simple_request("DELETE", host, url, query, auth_token, cookies, nc);
}

static char *body_request(const char *verb,
                          const char *host,
                          const char *url,
                          const char *ctype,
                          char **body_parts, int nparts,
                          const char *auth_token,
                          char **cookies, int nc)
{
    char *msg  = calloc(BUFLEN, 1);
    char  body[BUFLEN] = {0};
    char  line[LINELEN];

    if (body_parts && nparts) {
        if (strcmp(ctype, "application/json") == 0) {
            strncpy(body, body_parts[0], BUFLEN - 1);
        } else {
            for (int i = 0; i < nparts; i++) {
                strcat(body, body_parts[i]);
                if (i < nparts - 1)
                    strcat(body, "&");
            }
        }
    }

    sprintf(line, "%s %s HTTP/1.1", verb, url);
    compute_message(msg, line);

    add_std_headers(msg, host, auth_token);

    sprintf(line, "Content-Type: %s", ctype);
    compute_message(msg, line);

    sprintf(line, "Content-Length: %zu", strlen(body));
    compute_message(msg, line);

    add_cookies(msg, cookies, nc);
    compute_message(msg, "");

    strcat(msg, body);
    return msg;
}

char *compute_post_request(const char *host, const char *url,
                           const char *ctype,
                           char **body_parts, int nparts,
                           const char *auth_token,
                           char **cookies, int nc)
{
    return body_request("POST", host, url, ctype,
                        body_parts, nparts,
                        auth_token, cookies, nc);
}

char *compute_put_request(const char *host, const char *url,
                          const char *ctype,
                          char **body_parts, int nparts,
                          const char *auth_token,
                          char **cookies, int nc)
{
    return body_request("PUT", host, url, ctype,
                        body_parts, nparts,
                        auth_token, cookies, nc);
}
