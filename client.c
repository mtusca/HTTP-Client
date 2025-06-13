#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define HOST_IP   "63.32.125.183"
#define PORT_NO   8081
#define HOST_HDR  HOST_IP

static void chop_nl(char *s)
{
    size_t n = strlen(s);
    if (n && s[n - 1] == '\n')
        s[n - 1] = 0;
}

static void ask(const char *field, char *dst, size_t mx)
{
    printf("%s=", field);
    fflush(stdout);
    if (!fgets(dst, (int)mx, stdin))
        dst[0] = '\0';
    chop_nl(dst);
}

static int http_code(const char *resp)
{
    const char *p = strstr(resp, "HTTP/1.1 ");
    if (p == NULL)
        return 0;
    return atoi(p + 9);
}

static int is_success(int code)
{
    return code >= 200 && code < 300;
}

static char *xchg(char *req)
{
    int sock = open_connection(HOST_IP, PORT_NO, AF_INET, SOCK_STREAM, 0);
    send_to_server(sock, req);
    char *resp = receive_from_server(sock);
    close_connection(sock);
    return resp;
}

static char *pull_cookie(const char *resp)
{
    const char *p = strstr(resp, "Set-Cookie: ");
    if (!p)
        return NULL;

    p += 12;
    const char *e = strchr(p, ';');
    if (!e)
        e = strstr(p, "\r\n");

    size_t n = (size_t)(e - p);
    char *c  = calloc(n + 1, 1);
    memcpy(c, p, n);
    return c;
}

static char *cookie = NULL;
static char *jwt    = NULL;
enum { NO_ROLE, ADMIN, USER } role = NO_ROLE;

static int  *known_ids = NULL;
static int   known_cnt = 0;
static int   known_cap = 0;

static void remember_movie(int id)
{
    for (int i = 0; i < known_cnt; i++)
        if (known_ids[i] == id)
            return;

    if (known_cnt == known_cap) {
        if (known_cap)
            known_cap *= 2;
        else
            known_cap = 16;
        known_ids = realloc(known_ids, known_cap * sizeof(int));
    }

    known_ids[known_cnt++] = id;
}

static int id_known(int id)
{
    for (int i = 0; i < known_cnt; i++)
        if (known_ids[i] == id)
            return 1;
    return 0;
}

static void success(const char *msg) { printf("SUCCESS: %s\n", msg); }
static void failure(const char *msg) { printf("ERROR: %s\n",   msg); }

static void print_users(const char *json)
{
    JSON_Value *v = json_parse_string(json);
    JSON_Array *u = json_object_get_array(json_value_get_object(v), "users");

    success("Lista utilizatorilor");
    for (size_t i = 0; i < json_array_get_count(u); i++) {
        JSON_Object *o = json_array_get_object(u, i);
        printf("#%d %s:%s\n",
               (int)json_object_get_number(o, "id"),
               json_object_get_string(o, "username"),
               json_object_get_string(o, "password"));
    }

    json_value_free(v);
}

static void print_movies(const char *json)
{
    JSON_Value *v = json_parse_string(json);
    JSON_Array *a = json_object_get_array(json_value_get_object(v), "movies");

    success("Lista filmelor");
    for (size_t i = 0; i < json_array_get_count(a); i++) {
        JSON_Object *m = json_array_get_object(a, i);
        int id = (int)json_object_get_number(m, "id");
        printf("#%d %s\n", id, json_object_get_string(m, "title"));
        remember_movie(id);
    }

    json_value_free(v);
}

static void print_collections(const char *json)
{
    JSON_Value *v = json_parse_string(json);
    JSON_Array *a = json_object_get_array(json_value_get_object(v), "collections");

    success("Lista colecțiilor");
    for (size_t i = 0; i < json_array_get_count(a); i++) {
        JSON_Object *c = json_array_get_object(a, i);
        printf("#%d: %s\n",
               (int)json_object_get_number(c, "id"),
               json_object_get_string(c, "title"));
    }

    json_value_free(v);
}

static void cmd_login_admin(void)
{
    char user[100], pass[100];
    ask("username", user, sizeof user);
    ask("password", pass, sizeof pass);

    JSON_Value  *jv  = json_value_init_object();
    JSON_Object *obj = json_value_get_object(jv);
    json_object_set_string(obj, "username", user);
    json_object_set_string(obj, "password", pass);

    char *body = json_serialize_to_string(jv);
    char *arr[1] = { body };

    char *req = compute_post_request(HOST_HDR,
                                     "/api/v1/tema/admin/login",
                                     "application/json",
                                     arr, 1,
                                     NULL, NULL, 0);

    char *resp = xchg(req);

    if (is_success(http_code(resp))) {
        free(cookie);
        cookie = pull_cookie(resp);
        role   = ADMIN;
        success("Admin autentificat");
    } else {
        failure("Autentificare esuata");
    }

    json_free_serialized_string(body);
    json_value_free(jv);
    free(req);
    free(resp);
}

static void cmd_add_user(void)
{
    if (role != ADMIN) {
        failure("Lipsa rol admin");
        return;
    }

    char u[100], p[100];
    ask("username", u, sizeof u);
    ask("password", p, sizeof p);

    JSON_Value  *jv  = json_value_init_object();
    JSON_Object *o   = json_value_get_object(jv);
    json_object_set_string(o, "username", u);
    json_object_set_string(o, "password", p);

    char *body = json_serialize_to_string(jv);
    char *arr[1] = { body };
    char *ck [1] = { cookie };

    char *req = compute_post_request(HOST_HDR,
                                     "/api/v1/tema/admin/users",
                                     "application/json",
                                     arr, 1,
                                     NULL, ck, 1);

    char *resp = xchg(req);

    if (is_success(http_code(resp)))
        success("Utilizator adaugat");
    else
        failure("Operatie esuata");

    json_free_serialized_string(body);
    json_value_free(jv);
    free(req);
    free(resp);
}

static void cmd_get_users(void)
{
    if (role != ADMIN) {
        failure("Lipsa rol admin");
        return;
    }

    char *ck [1] = { cookie };
    char *req    = compute_get_request(HOST_HDR,
                                       "/api/v1/tema/admin/users",
                                       NULL, NULL,
                                       ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp)))
        print_users(basic_extract_json_response(resp));
    else
        failure("Operatie esuata");

    free(req);
    free(resp);
}

static void cmd_delete_user(void)
{
    if (role != ADMIN) {
        failure("Lipsa rol admin");
        return;
    }

    char uname[100];
    ask("username", uname, sizeof uname);

    char url[256];
    sprintf(url, "/api/v1/tema/admin/users/%s", uname);

    char *ck [1] = { cookie };
    char *req    = compute_delete_request(HOST_HDR, url,
                                          NULL, NULL,
                                          ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp)))
        success("Utilizator sters");
    else
        failure("Operatie esuata");

    free(req);
    free(resp);
}

static void cmd_logout_admin(void)
{
    if (role != ADMIN) {
        failure("Niciun admin logat");
        return;
    }

    char *ck [1] = { cookie };
    char *req    = compute_get_request(HOST_HDR,
                                       "/api/v1/tema/admin/logout",
                                       NULL, NULL,
                                       ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp))) {
        success("Admin delogat");
        free(cookie);
        cookie = NULL;
        role   = NO_ROLE;
    } else {
        failure("Operatie esuata");
    }

    free(req);
    free(resp);
}

static void cmd_login_user(void)
{
    char auser[100], user[100], pass[100];
    ask("admin_username", auser, sizeof auser);
    ask("username",       user,  sizeof user);
    ask("password",       pass,  sizeof pass);

    JSON_Value  *jv  = json_value_init_object();
    JSON_Object *obj = json_value_get_object(jv);
    json_object_set_string(obj, "admin_username", auser);
    json_object_set_string(obj, "username",       user);
    json_object_set_string(obj, "password",       pass);

    char *body = json_serialize_to_string(jv);
    char *arr[1] = { body };

    char *req  = compute_post_request(HOST_HDR,
                                      "/api/v1/tema/user/login",
                                      "application/json",
                                      arr, 1,
                                      NULL, NULL, 0);
    char *resp = xchg(req);

    if (is_success(http_code(resp))) {
        free(cookie);
        cookie = pull_cookie(resp);
        role   = USER;
        success("Autentificare reusita");
    } else {
        failure("Autentificare esuata");
    }

    json_free_serialized_string(body);
    json_value_free(jv);
    free(req);
    free(resp);
}

static void cmd_get_access(void)
{
    if (role != USER) {
        failure("Necesita logare utilizator");
        return;
    }

    char *ck [1] = { cookie };
    char *req    = compute_get_request(HOST_HDR,
                                       "/api/v1/tema/library/access",
                                       NULL, NULL,
                                       ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp))) {
        JSON_Value *v = json_parse_string(basic_extract_json_response(resp));
        free(jwt);
        jwt = strdup(json_object_get_string(json_value_get_object(v), "token"));
        json_value_free(v);
        success("Token JWT primit");
    } else {
        failure("Operatie esuata");
    }

    free(req);
    free(resp);
}

static void cmd_logout_user(void)
{
    if (role != USER) {
        failure("Niciun utilizator logat");
        return;
    }

    char *ck [1] = { cookie };
    char *req    = compute_get_request(HOST_HDR,
                                       "/api/v1/tema/user/logout",
                                       NULL, NULL,
                                       ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp))) {
        success("Utilizator delogat");
        free(cookie);
        cookie = NULL;
        free(jwt);
        jwt    = NULL;
        role   = NO_ROLE;
    } else {
        failure("Operatie esuata");
    }

    free(req);
    free(resp);
}

#define NEED_TOKEN()                       \
    do {                                   \
        if (!jwt) {                        \
            failure("Fara acces library"); \
            return;                        \
        }                                  \
    } while (0)

static void cmd_get_movies(void)
{
    NEED_TOKEN();

    char *ck [1] = { cookie };
    char *req    = compute_get_request(HOST_HDR,
                                       "/api/v1/tema/library/movies",
                                       NULL, jwt,
                                       ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp)))
        print_movies(basic_extract_json_response(resp));
    else
        failure("Operatie esuata");

    free(req);
    free(resp);
}

static void cmd_get_movie(void)
{
    NEED_TOKEN();

    char idbuf[16];
    ask("id", idbuf, sizeof idbuf);
    int id = atoi(idbuf);

    char url[128];
    sprintf(url, "/api/v1/tema/library/movies/%d", id);

    char *ck [1] = { cookie };
    char *req    = compute_get_request(HOST_HDR, url,
                                       NULL, jwt,
                                       ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp))) {
        success("Detalii film");
        JSON_Value  *v = json_parse_string(basic_extract_json_response(resp));
        JSON_Object *o = json_value_get_object(v);

        printf("title: %s\n",       json_object_get_string(o, "title"));
        printf("year: %d\n",        (int)json_object_get_number(o, "year"));
        printf("description: %s\n", json_object_get_string(o, "description"));

        if (json_object_has_value_of_type(o, "rating", JSONNumber))
            printf("rating: %.1f\n", json_object_get_number(o, "rating"));
        else
            printf("rating: %s\n", json_object_get_string(o, "rating"));

        json_value_free(v);
    } else {
        failure("Film inexistent sau fara acces");
    }

    free(req);
    free(resp);
}

static void cmd_add_movie(void)
{
    NEED_TOKEN();

    char title[256], desc[512], ybuf[16], rbuf[16];
    ask("title",       title, sizeof title);
    ask("year",        ybuf,  sizeof ybuf);
    ask("description", desc,  sizeof desc);
    ask("rating",      rbuf,  sizeof rbuf);

    int    year   = atoi(ybuf);
    double rating = atof(rbuf);

    if (rating < 0 || rating > 10) {
        failure("Rating invalid");
        return;
    }

    JSON_Value  *v  = json_value_init_object();
    JSON_Object *o  = json_value_get_object(v);
    json_object_set_string(o, "title",       title);
    json_object_set_number(o, "year",        year);
    json_object_set_string(o, "description", desc);
    json_object_set_number(o, "rating",      rating);

    char *body = json_serialize_to_string(v);
    char *arr[1] = { body };
    char *ck [1] = { cookie };

    char *req  = compute_post_request(HOST_HDR,
                                      "/api/v1/tema/library/movies",
                                      "application/json",
                                      arr, 1,
                                      jwt, ck, 1);
    char *resp = xchg(req);

    if (is_success(http_code(resp))) {
        JSON_Value *rv = json_parse_string(basic_extract_json_response(resp));
        remember_movie((int)json_object_get_number(json_value_get_object(rv), "id"));
        json_value_free(rv);
        success("Film adaugat");
    } else {
        failure("Operatie esuata");
    }

    json_free_serialized_string(body);
    json_value_free(v);
    free(req);
    free(resp);
}

static void cmd_update_movie(void)
{
    NEED_TOKEN();

    char idbuf[16];
    ask("id", idbuf, sizeof idbuf);
    int id = atoi(idbuf);

    char title[256] = "", desc[512] = "", ybuf[16] = "", rbuf[16] = "";
    ask("title",       title, sizeof title);
    ask("year",        ybuf,  sizeof ybuf);
    ask("description", desc,  sizeof desc);
    ask("rating",      rbuf,  sizeof rbuf);

    JSON_Value  *v  = json_value_init_object();
    JSON_Object *o  = json_value_get_object(v);

    if (*title)
        json_object_set_string(o, "title", title);
    if (*ybuf)
        json_object_set_number(o, "year", atoi(ybuf));
    if (*desc)
        json_object_set_string(o, "description", desc);
    if (*rbuf) {
        double r = atof(rbuf);
        if (r < 0 || r > 10) {
            failure("Rating invalid");
            json_value_free(v);
            return;
        }
        json_object_set_number(o, "rating", r);
    }

    char *body = json_serialize_to_string(v);
    char *arr[1] = { body };
    char *ck [1] = { cookie };

    char url[128];
    sprintf(url, "/api/v1/tema/library/movies/%d", id);

    char *req  = compute_put_request(HOST_HDR, url,
                                     "application/json",
                                     arr, 1,
                                     jwt, ck, 1);
    char *resp = xchg(req);

    if (is_success(http_code(resp)))
        success("Film actualizat");
    else
        failure("Operatie esuata");

    json_free_serialized_string(body);
    json_value_free(v);
    free(req);
    free(resp);
}

static void cmd_delete_movie(void)
{
    NEED_TOKEN();

    char idbuf[16];
    ask("id", idbuf, sizeof idbuf);
    int id = atoi(idbuf);

    char url[128];
    sprintf(url, "/api/v1/tema/library/movies/%d", id);

    char *ck [1] = { cookie };
    char *req    = compute_delete_request(HOST_HDR, url,
                                          NULL, jwt,
                                          ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp)))
        success("Film sters");
    else
        failure("Operatie esuata");

    free(req);
    free(resp);
}

static int post_movie_to_collection(int cid, int mid)
{
    char url[160];
    sprintf(url, "/api/v1/tema/library/collections/%d/movies", cid);

    JSON_Value *v = json_value_init_object();
    json_object_set_number(json_value_get_object(v), "id", mid);

    char *body = json_serialize_to_string(v);
    char *arr[1] = { body };
    char *ck [1] = { cookie };

    int ok = 0;
    for (int tr = 0; tr < 3 && !ok; tr++) {
        char *req  = compute_post_request(HOST_HDR, url,
                                          "application/json",
                                          arr, 1,
                                          jwt, ck, 1);
        char *resp = xchg(req);
        if (is_success(http_code(resp)))
            ok = 1;
        free(req);
        free(resp);
    }

    json_free_serialized_string(body);
    json_value_free(v);
    return ok;
}

static void cmd_get_collections(void)
{
    NEED_TOKEN();

    char *ck [1] = { cookie };
    char *req    = compute_get_request(HOST_HDR,
                                       "/api/v1/tema/library/collections",
                                       NULL, jwt,
                                       ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp)))
        print_collections(basic_extract_json_response(resp));
    else
        failure("Operatie esuata");

    free(req);
    free(resp);
}

static void cmd_get_collection(void)
{
    NEED_TOKEN();

    char idbuf[16];
    ask("id", idbuf, sizeof idbuf);
    int cid = atoi(idbuf);

    char url[128];
    sprintf(url, "/api/v1/tema/library/collections/%d", cid);

    char *ck [1] = { cookie };
    char *req    = compute_get_request(HOST_HDR, url,
                                       NULL, jwt,
                                       ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp))) {
        success("Detalii colecție");
        JSON_Value  *v = json_parse_string(basic_extract_json_response(resp));
        JSON_Object *o = json_value_get_object(v);

        printf("title: %s\n", json_object_get_string(o, "title"));
        printf("owner: %s\n", json_object_get_string(o, "owner"));

        JSON_Array *mv = json_object_get_array(o, "movies");
        for (size_t i = 0; i < json_array_get_count(mv); i++) {
            JSON_Object *m = json_array_get_object(mv, i);
            printf("#%d: %s\n",
                   (int)json_object_get_number(m, "id"),
                   json_object_get_string(m, "title"));
        }

        json_value_free(v);
    } else {
        failure("Operatie esuata");
    }

    free(req);
    free(resp);
}

static void cmd_add_collection(void)
{
    NEED_TOKEN();

    char title[256], nbuf[16];
    ask("title",      title, sizeof title);
    ask("num_movies", nbuf,  sizeof nbuf);

    int n = atoi(nbuf);
    if (n <= 0) {
        failure("Date invalide");
        return;
    }

    int *ids = calloc(n, sizeof(int));
    int  bad = 0;

    for (int i = 0; i < n; i++) {
        char f[32];
        sprintf(f, "movie_id[%d]", i);
        char tmp[32];
        ask(f, tmp, sizeof tmp);
        ids[i] = atoi(tmp);
        if (!id_known(ids[i]))
            bad = 1;
    }

    if (bad) {
        free(ids);
        failure("Date invalide");
        return;
    }

    JSON_Value *v = json_value_init_object();
    json_object_set_string(json_value_get_object(v), "title", title);

    char *body = json_serialize_to_string(v);
    char *arr[1] = { body };
    char *ck [1] = { cookie };

    char *req  = compute_post_request(HOST_HDR,
                                      "/api/v1/tema/library/collections",
                                      "application/json",
                                      arr, 1,
                                      jwt, ck, 1);
    char *resp = xchg(req);

    int cid = -1;
    if (is_success(http_code(resp))) {
        JSON_Value *rv = json_parse_string(basic_extract_json_response(resp));
        cid = (int)json_object_get_number(json_value_get_object(rv), "id");
        json_value_free(rv);
    }

    if (cid < 0) {
        failure("Operatie esuata");
    } else {
        int ok_all = 1;
        for (int i = 0; i < n; i++)
            if (!post_movie_to_collection(cid, ids[i]))
                ok_all = 0;

        if (ok_all)
            success("Colectie adaugata");
        else
            failure("Operatie esuata");
    }

    free(ids);
    json_free_serialized_string(body);
    json_value_free(v);
    free(req);
    free(resp);
}

static void cmd_delete_collection(void)
{
    NEED_TOKEN();

    char idbuf[16];
    ask("id", idbuf, sizeof idbuf);
    int cid = atoi(idbuf);

    char url[128];
    sprintf(url, "/api/v1/tema/library/collections/%d", cid);

    char *ck [1] = { cookie };
    char *req    = compute_delete_request(HOST_HDR, url,
                                          NULL, jwt,
                                          ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp)))
        success("Colectie stearsa");
    else
        failure("Operatie esuata");

    free(req);
    free(resp);
}

static void cmd_add_movie_to_collection(void)
{
    NEED_TOKEN();

    char cbuf[16], mbuf[16];
    ask("collection_id", cbuf, sizeof cbuf);
    ask("movie_id",      mbuf, sizeof mbuf);

    int cid = atoi(cbuf);
    int mid = atoi(mbuf);

    if (post_movie_to_collection(cid, mid))
        success("Film adaugat in colectie");
    else
        failure("Operatie esuata");
}

static void cmd_delete_movie_from_collection(void)
{
    NEED_TOKEN();

    char cbuf[16], mbuf[16];
    ask("collection_id", cbuf, sizeof cbuf);
    ask("movie_id",      mbuf, sizeof mbuf);

    int cid = atoi(cbuf);
    int mid = atoi(mbuf);

    char url[160];
    sprintf(url, "/api/v1/tema/library/collections/%d/movies/%d", cid, mid);

    char *ck [1] = { cookie };
    char *req    = compute_delete_request(HOST_HDR, url,
                                          NULL, jwt,
                                          ck, 1);
    char *resp   = xchg(req);

    if (is_success(http_code(resp)))
        success("Film sters din colectie");
    else
        failure("Operatie esuata");

    free(req);
    free(resp);
}

struct entry { const char *cmd; void (*fn)(void); };

static struct entry tbl[] = {
    {"login_admin",                 cmd_login_admin},
    {"add_user",                    cmd_add_user},
    {"get_users",                   cmd_get_users},
    {"delete_user",                 cmd_delete_user},
    {"logout_admin",                cmd_logout_admin},
    {"login",                       cmd_login_user},
    {"get_access",                  cmd_get_access},
    {"logout",                      cmd_logout_user},
    {"get_movies",                  cmd_get_movies},
    {"get_movie",                   cmd_get_movie},
    {"add_movie",                   cmd_add_movie},
    {"update_movie",                cmd_update_movie},
    {"delete_movie",                cmd_delete_movie},
    {"get_collections",             cmd_get_collections},
    {"get_collection",              cmd_get_collection},
    {"add_collection",              cmd_add_collection},
    {"delete_collection",           cmd_delete_collection},
    {"add_movie_to_collection",     cmd_add_movie_to_collection},
    {"delete_movie_from_collection",cmd_delete_movie_from_collection},
    {NULL,                          NULL}
};

int main(void)
{
    char line[LINELEN];

    while (fgets(line, LINELEN, stdin)) {
        chop_nl(line);

        if (strcmp(line, "exit") == 0)
            break;

        int handled = 0;
        for (int i = 0; tbl[i].cmd; i++) {
            if (strcmp(line, tbl[i].cmd) == 0) {
                tbl[i].fn();
                handled = 1;
                break;
            }
        }

        if (!handled)
            puts("ERROR: Comanda necunoscuta");
    }

    free(cookie);
    free(jwt);
    free(known_ids);
    return 0;
}
