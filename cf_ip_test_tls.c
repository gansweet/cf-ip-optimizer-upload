/*
 * cf_ip_test_tls.c — Amos · CF 优选：测速内核 + 内置 Web 服务（前后端一体，启动即打开页面）
 *
 * 编译：cc -O2 -Wall -Wextra -o cfip cf_ip_test_tls.c $(pkg-config --cflags --libs libcurl) -lpthread
 * 运行：./cfip [--no-browser] [端口=18443] [前端文件]       开机自启：./cfip --autostart [端口]
 * 环境变量：CFIP_BIND 监听地址（默认 127.0.0.1）、CFIP_HOME 数据目录、CFIP_NO_BROWSER 不自动打开浏览器
 * TLS 证书与域名验证始终开启；SNI 请使用自己拥有或获授权测试的域名。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 18443
#define MAXIP 3000
#define REQ_MAX 262144
#define BODY_MAX (512 * 1024)

#define DEF4 "173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n141.101.64.0/18\n108.162.192.0/18\n" \
             "190.93.240.0/20\n188.114.96.0/20\n197.234.240.0/22\n198.41.128.0/17\n162.158.0.0/15\n104.16.0.0/13\n" \
             "104.24.0.0/14\n172.64.0.0/13\n131.0.72.0/22\n"
#define DEF6 "2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n2405:b500::/32\n2405:8100::/32\n2a06:98c0::/29\n2c0f:f248::/32\n"

/* 一个候选：IP 或域名 + 端口 */
typedef struct { char host[128], suf[64]; int port, dom, keep, ok, tries; double ms, mbps; } Item;   /* keep：用户手动保留的条目，自带后缀优先 */
typedef struct { const char *sni[8]; int nsni, port, timeout, tries, threads; } Prm;
typedef struct { char host[200], path[400]; int secs; } Dl;
typedef struct { char name[96], suf[96]; int cnt; } Rule;
typedef struct { char *d; size_t n; } Buf;
typedef struct { const char *d; size_t n, o; } Src;

static Prm P;
static Dl DL;
static Item *res;                                   /* 最近一次筛选结果 */
static int nres, running, done, total;
static int e_to, e_cert, e_conn, e_oth;             /* 失败原因统计 */
static char phase[1600] = "空闲", links[2048], notes[240], secrets[4096], cfg[REQ_MAX];
static char self[4096], exe_dir[4096], wd[4096], page[4200], html_path[4200];
static time_t last_run;
static int g_port = DEFAULT_PORT;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t rs = 88172645463325252ULL;
static __thread char ferr[400];
static __thread const char *xhdr;

/* ---------- libcurl 公共设置 ---------- */
static void ca(CURL *c) {
#ifdef __ANDROID__
    curl_easy_setopt(c, CURLOPT_CAPATH, access("/apex/com.android.conscrypt/cacerts", R_OK) ? "/system/etc/security/cacerts" : "/apex/com.android.conscrypt/cacerts");
#endif
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "cfip/3.0");
}
static void direct(CURL *c) { curl_easy_setopt(c, CURLOPT_PROXY, ""); }   /* 测速一律直连，忽略环境变量里的代理 */

/* ---------- 小工具 ---------- */
static void setphase(const char *s) { pthread_mutex_lock(&mu); snprintf(phase, sizeof phase, "%s", s); pthread_mutex_unlock(&mu); }
static void addphase(const char *s) { pthread_mutex_lock(&mu); size_t L = strlen(phase); snprintf(phase + L, sizeof phase - L, "%s", s); pthread_mutex_unlock(&mu); }
static void prog(int t) { pthread_mutex_lock(&mu); done = 0; total = t; pthread_mutex_unlock(&mu); }
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)(rs >> 16); }
static void shuffle(char **a, int n) { for (int i = n - 1; i > 0; i--) { int j = (int)(rnd() % (uint32_t)(i + 1)); char *t = a[i]; a[i] = a[j]; a[j] = t; } }
static int sh(const char *fmt, ...) {
    char cmd[1024]; va_list ap;
    va_start(ap, fmt); vsnprintf(cmd, sizeof cmd, fmt, ap); va_end(ap);
    return system(cmd);
}
static int safe(const char *s) {                     /* 文件名 / 用户名：字母数字 . _ -，且不以 . 开头 */
    if (!*s || *s == '.') return 0;
    for (; *s; s++) if (!isalnum((unsigned char)*s) && !strchr("._-", *s)) return 0;
    return 1;
}
static int host_ok(const char *s) {                  /* 域名：字母数字 . - _，至少一个点 */
    size_t n = strlen(s); if (!n || n > 127 || !strchr(s, '.')) return 0;
    for (; *s; s++) if (!isalnum((unsigned char)*s) && !strchr(".-_", *s)) return 0;
    return 1;
}
static int suf_ok(const char *s) {                   /* 后缀可以是任何文字 / emoji，只禁止控制字符和竖线 */
    for (; *s; s++) if ((unsigned char)*s < 32 || *s == 127 || *s == '|') return 0;
    return 1;
}
static int mail_ok(const char *s) {
    if (!strchr(s, '@')) return 0;
    for (; *s; s++) if (!isalnum((unsigned char)*s) && !strchr("@._-+", *s)) return 0;
    return 1;
}
static int has_proto(const char *p) {
    const curl_version_info_data *v = curl_version_info(CURLVERSION_NOW);
    for (const char *const *q = v->protocols; q && *q; q++) if (!strcmp(*q, p)) return 1;
    return 0;
}

/* ---------- urlencoded 表单 ---------- */
static void form_get(const char *body, const char *key, char *out, size_t n) {
    size_t kl = strlen(key); out[0] = 0;
    for (const char *p = body; p && *p;) {
        if (!strncmp(p, key, kl) && p[kl] == '=') {
            size_t o = 0; p += kl + 1;
            while (*p && *p != '&' && o + 1 < n) {
                if (*p == '+') out[o++] = ' ';
                else if (*p == '%' && isxdigit((unsigned char)p[1]) && isxdigit((unsigned char)p[2])) {
                    char h[3] = { p[1], p[2], 0 }; out[o++] = (char)strtol(h, NULL, 16); p += 2;
                } else out[o++] = *p;
                p++;
            }
            out[o] = 0; return;
        }
        p = strchr(p, '&'); if (p) p++;
    }
}
static int form_int(const char *b, const char *k, int def, int lo, int hi) {
    char t[32]; form_get(b, k, t, sizeof t);
    if (!t[0]) return def;
    int v = atoi(t); return v < lo ? lo : v > hi ? hi : v;
}
static void urlenc(const char *s, char *o, size_t n) {
    size_t k = 0;
    for (; *s && k + 4 < n; s++) {
        if (isalnum((unsigned char)*s) || strchr("-._~", *s)) o[k++] = *s;
        else k += (size_t)snprintf(o + k, n - k, "%%%02X", (unsigned char)*s);
    }
    o[k] = 0;
}

/* 密钥单独保存在 data/secrets.txt，不随配置回显 */
static const char *SEC[] = { "gh_token", "gh_git_token", "sf_pass", "tg_token", "mail_pass", NULL };
static void getv(const char *c, const char *k, char *o, size_t n) { form_get(c, k, o, n); if (!o[0]) form_get(secrets, k, o, n); }
static void save_secrets(const char *body) {         /* 表单里填了新值才覆盖旧值 */
    char *ns = malloc(sizeof secrets); if (!ns) return;
    size_t o = 0; ns[0] = 0;
    for (int i = 0; SEC[i]; i++) {
        char v[256], e[800]; form_get(body, SEC[i], v, sizeof v);
        if (!v[0]) form_get(secrets, SEC[i], v, sizeof v);
        if (v[0]) { urlenc(v, e, sizeof e); o += (size_t)snprintf(ns + o, sizeof secrets - o, "%s%s=%s", o ? "&" : "", SEC[i], e); }
    }
    snprintf(secrets, sizeof secrets, "%s", ns); free(ns);
    FILE *f = fopen("data/secrets.txt", "w"); if (f) { fputs(secrets, f); fclose(f); }
}
static void strip_sec(const char *in, char *out, size_t n) {
    size_t o = 0; out[0] = 0;
    for (const char *p = in; *p;) {
        const char *e = strchr(p, '&'); size_t l = e ? (size_t)(e - p) : strlen(p); int sec = 0;
        for (int i = 0; SEC[i]; i++) { size_t kl = strlen(SEC[i]); if (!strncmp(p, SEC[i], kl) && p[kl] == '=') sec = 1; }
        if (!sec && o + l + 2 < n) { if (o) out[o++] = '&'; memcpy(out + o, p, l); o += l; out[o] = 0; }
        p += l; if (*p == '&') p++;
    }
}

/* ---------- HTTP 客户端 ---------- */
static size_t wcb(char *p, size_t s, size_t m, void *u) {
    Buf *b = u; size_t k = s * m;
    if (b->n + k > BODY_MAX) return 0;
    char *nd = realloc(b->d, b->n + k + 1); if (!nd) return 0;
    b->d = nd; memcpy(b->d + b->n, p, k); b->n += k; b->d[b->n] = 0; return k;
}
static size_t nowrite(char *p, size_t s, size_t m, void *u) { (void)p; (void)u; return s * m; }
static size_t rcb(char *p, size_t s, size_t m, void *u) {
    Src *r = u; size_t k = s * m; if (k > r->n - r->o) k = r->n - r->o;
    memcpy(p, r->d + r->o, k); r->o += k; return k;
}
static char *fetch(const char *url) {                /* 下载网段 / 域名列表；失败原因写入 ferr */
    Buf b = { 0 }; ferr[0] = 0;
    CURL *c = curl_easy_init(); if (!c) { snprintf(ferr, sizeof ferr, "curl 初始化失败"); return NULL; }
    ca(c); direct(c); curl_easy_setopt(c, CURLOPT_URL, url); curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wcb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &b); curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    CURLcode rc = curl_easy_perform(c); long st = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &st); curl_easy_cleanup(c);
    if (rc != CURLE_OK) snprintf(ferr, sizeof ferr, "拉取失败：%s", curl_easy_strerror(rc));
    else if (st < 200 || st >= 300) snprintf(ferr, sizeof ferr, "拉取失败：HTTP %ld", st);
    if (ferr[0]) { free(b.d); return NULL; }
    return b.d ? b.d : strdup("");
}

/* ---------- 代理 / VPN 检测（仅提示，不阻止运行） ---------- */
static int proxy_check(char *why, size_t n) {
    why[0] = 0;
    const char *ev[] = { "http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", NULL };
    for (int i = 0; ev[i]; i++) { const char *v = getenv(ev[i]); if (v && *v) { snprintf(why, n, "程序环境变量 %s 设置了代理", ev[i]); return 1; } }
    struct addrinfo hints, *ai = NULL; memset(&hints, 0, sizeof hints); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (!getaddrinfo("www.cloudflare.com", NULL, &hints, &ai)) {
        for (struct addrinfo *a = ai; a; a = a->ai_next) {
            uint32_t ip = ntohl(((struct sockaddr_in *)a->ai_addr)->sin_addr.s_addr);
            if ((ip >> 17) == (0xC6120000u >> 17)) {          /* 198.18.0.0/15：代理软件 fake-ip */
                snprintf(why, n, "域名解析返回 198.18.x.x（代理软件的 fake-ip 模式）"); freeaddrinfo(ai); return 1;
            }
        }
        freeaddrinfo(ai);
    }
    struct ifaddrs *ifs = NULL;
    if (!getifaddrs(&ifs)) {
        const char *pre[] = { "tun", "tap", "wg", "ppp", "tailscale", "zt", "clash", "Meta", "mihomo", "nekoray", "CloudflareWARP",
#ifndef __APPLE__
                              "utun",
#endif
                              NULL };
        for (struct ifaddrs *i = ifs; i && !why[0]; i = i->ifa_next) {
            if (!i->ifa_name || !(i->ifa_flags & IFF_UP)) continue;
            for (int k = 0; pre[k]; k++) if (!strncmp(i->ifa_name, pre[k], strlen(pre[k]))) { snprintf(why, n, "检测到网卡 %s（可能是代理 / VPN 的虚拟网卡）", i->ifa_name); break; }
        }
        freeifaddrs(ifs);
    }
    return why[0] != 0;
}

/* ---------- 候选：IP / 域名 + 端口 ---------- */
static int parse_entry(char *l, Item *it) {          /* host[:port][#后缀]、[v6]:port、纯 IPv6 */
    memset(it, 0, sizeof *it); it->port = 443;
    char *h = strchr(l, '#'); if (h) { *h++ = 0; snprintf(it->suf, sizeof it->suf, "#%s", h); }
    while (isspace((unsigned char)*l)) l++;
    for (char *e = l + strlen(l); e > l && isspace((unsigned char)e[-1]);) *--e = 0;
    if (*l == '[') { char *e = strchr(l, ']'); if (!e) return 0; *e = 0; if (e[1] == ':') it->port = atoi(e + 2); l++; }
    else { char *c = strchr(l, ':'); if (c && !strchr(c + 1, ':')) { *c = 0; it->port = atoi(c + 1); } }
    if (!*l || strlen(l) >= sizeof it->host || it->port < 1 || it->port > 65535) return 0;
    unsigned char a[16];
    if (inet_pton(AF_INET, l, a) == 1 || inet_pton(AF_INET6, l, a) == 1) it->dom = 0;
    else if (host_ok(l)) it->dom = 1;
    else return 0;
    snprintf(it->host, sizeof it->host, "%s", l); return 1;
}
/* 输出格式：443 不写端口；其他端口写成 ip:端口 / [v6]:端口 / 域名:端口；后缀原样追加 */
static void fmt_entry(const Item *it, const char *suf, char *o, size_t n) {
    const char *s = (it->keep && it->suf[0]) ? it->suf : suf[0] ? suf : it->suf; int v6 = strchr(it->host, ':') != NULL;
    if (it->port == 443) snprintf(o, n, "%s%s", it->host, s);
    else if (v6) snprintf(o, n, "[%s]:%d%s", it->host, it->port, s);
    else snprintf(o, n, "%s:%d%s", it->host, it->port, s);
}
static int add_item(Item *c, int n, const char *host, int dom) {
    if (n >= MAXIP) return n;
    for (int k = 0; k < n; k++) if (c[k].port == P.port && !strcmp(c[k].host, host)) return n;
    memset(&c[n], 0, sizeof c[n]); snprintf(c[n].host, sizeof c[n].host, "%s", host);
    c[n].port = P.port; c[n].dom = dom; return n + 1;
}
/* 在网段内保留网络位、随机主机位，生成一个随机 IP */
static int sample(const char *cidr, char *out) {
    char t[96]; snprintf(t, sizeof t, "%s", cidr);
    char *s = strchr(t, '/'); if (!s) return 0;
    *s = 0; int pre = atoi(s + 1);
    int fam = strchr(t, ':') ? AF_INET6 : AF_INET, len = fam == AF_INET6 ? 16 : 4;
    unsigned char a[16];
    if (inet_pton(fam, t, a) != 1 || pre < 0 || pre > len * 8) return 0;
    for (int i = pre; i < len * 8; i++) {
        if (rnd() & 1) a[i / 8] |= (unsigned char)(0x80 >> (i % 8));
        else a[i / 8] &= (unsigned char)~(0x80 >> (i % 8));
    }
    return inet_ntop(fam, a, out, 48) != NULL;
}
/* 网段很多时：先随机打乱，取前 nseg 个网段（0 = 全部），每个网段由 C 生成 samples 个随机 IP */
static int gather(Item *c, int n, const char *txt, int samples, int nseg) {
    char *cp = strdup(txt), *sp = NULL, *seg[512]; int ns = 0; if (!cp) return n;
    for (char *l = strtok_r(cp, "\r\n ,;\t", &sp); l && ns < 512; l = strtok_r(NULL, "\r\n ,;\t", &sp)) if (strchr(l, '/') && l[0] != '#') seg[ns++] = l;
    shuffle(seg, ns); if (nseg > 0 && nseg < ns) ns = nseg;
    for (int s = 0; s < ns; s++)
        for (int j = 0; j < samples; j++) { char ip[48]; if (!sample(seg[s], ip)) break; n = add_item(c, n, ip, 0); }
    free(cp); return n;
}
static int gather_dom(Item *c, int n, const char *txt, int want) {
    char *cp = strdup(txt), *sp = NULL, *dm[1024]; int nd = 0; if (!cp) return n;
    for (char *l = strtok_r(cp, "\r\n", &sp); l; l = strtok_r(NULL, "\r\n", &sp)) {
        l[strcspn(l, "#")] = 0;                      /* # 之后是注释 */
        char *sp2 = NULL;
        for (char *t = strtok_r(l, " \t,;", &sp2); t && nd < 1024; t = strtok_r(NULL, " \t,;", &sp2)) if (host_ok(t)) dm[nd++] = t;
    }
    shuffle(dm, nd); if (want > 0 && want < nd) nd = want;
    for (int i = 0; i < nd; i++) n = add_item(c, n, dm[i], 1);
    free(cp); return n;
}

/* ---------- 真实 TLS 探测：IP 用 RESOLVE，域名用 CONNECT_TO，SNI 与证书校验始终开启 ---------- */
static struct curl_slist *setroute(CURL *c, const Item *it, const char *h) {
    char m[400]; struct curl_slist *l;
    if (it->dom) { snprintf(m, sizeof m, "%s:%d:%s:%d", h, it->port, it->host, it->port); l = curl_slist_append(NULL, m); curl_easy_setopt(c, CURLOPT_CONNECT_TO, l); }
    else { snprintf(m, sizeof m, strchr(it->host, ':') ? "%s:%d:[%s]" : "%s:%d:%s", h, it->port, it->host); l = curl_slist_append(NULL, m); curl_easy_setopt(c, CURLOPT_RESOLVE, l); }
    return l;
}
static void probe(Item *it, int salt) {
    double sum = 0; it->ok = 0; it->tries = P.tries;
    for (int t = 0; t < P.tries; t++) {
        const char *h = P.nsni ? P.sni[(salt + t) % P.nsni] : (it->dom ? it->host : "speed.cloudflare.com");
        char url[300]; CURL *c = curl_easy_init(); if (!c) continue;
        ca(c); direct(c);
        struct curl_slist *r = setroute(c, it, h);
        snprintf(url, sizeof url, "https://%s:%d/", h, it->port);
        curl_easy_setopt(c, CURLOPT_URL, url);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, (long)P.timeout); curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, (long)P.timeout + 1500L);
        curl_easy_setopt(c, CURLOPT_NOBODY, 1L); curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L); curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
        CURLcode rc = curl_easy_perform(c); curl_off_t ac = 0;
        curl_easy_getinfo(c, CURLINFO_APPCONNECT_TIME_T, &ac);       /* TCP + TLS 握手完成的时间（微秒） */
        if (ac > 0) { it->ok++; sum += (double)ac / 1000.0; }        /* 证书校验通过且握手完成即算成功，与 HTTP 状态码无关 */
        else if (rc == CURLE_OPERATION_TIMEDOUT) __sync_fetch_and_add(&e_to, 1);
        else if (rc == CURLE_PEER_FAILED_VERIFICATION || rc == CURLE_SSL_CERTPROBLEM || rc == CURLE_SSL_CACERT_BADFILE) __sync_fetch_and_add(&e_cert, 1);
        else if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_SSL_CONNECT_ERROR) __sync_fetch_and_add(&e_conn, 1);
        else __sync_fetch_and_add(&e_oth, 1);
        curl_slist_free_all(r); curl_easy_cleanup(c);
    }
    it->ms = it->ok ? sum / it->ok : 1e9;
}

static Item *wk; static int wn, wi;
static void *worker(void *a) {
    (void)a;
    for (;;) {
        pthread_mutex_lock(&mu); int i = wi++; pthread_mutex_unlock(&mu);
        if (i >= wn) return NULL;
        probe(&wk[i], i);
        pthread_mutex_lock(&mu); done++; pthread_mutex_unlock(&mu);
    }
}
static void run_pool(Item *w, int n) {
    pthread_t th[64]; int made = 0, t = P.threads < n ? P.threads : n;
    wk = w; wn = n; wi = 0;
    for (int i = 0; i < t; i++) if (!pthread_create(&th[made], NULL, worker, NULL)) made++;
    for (int i = 0; i < made; i++) pthread_join(th[i], NULL);
}

/* 下载测速：固定到该 IP / 域名，下载测速文件，返回 MB/s */
static double speed_test(const Item *it) {
    CURL *c = curl_easy_init(); if (!c) return 0;
    ca(c); direct(c);
    char url[700]; snprintf(url, sizeof url, "https://%s:%d%s", DL.host, it->port, DL.path);
    struct curl_slist *l = setroute(c, it, DL.host);
    curl_easy_setopt(c, CURLOPT_URL, url); curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, nowrite);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, (long)P.timeout); curl_easy_setopt(c, CURLOPT_TIMEOUT, (long)DL.secs);
    curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L); curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_perform(c);
    curl_off_t sz = 0, tot = 0, st = 0;
    curl_easy_getinfo(c, CURLINFO_SIZE_DOWNLOAD_T, &sz); curl_easy_getinfo(c, CURLINFO_TOTAL_TIME_T, &tot);
    curl_easy_getinfo(c, CURLINFO_STARTTRANSFER_TIME_T, &st);
    curl_slist_free_all(l); curl_easy_cleanup(c);
    double dt = (double)(tot - st) / 1e6;
    return (sz > 0 && dt > 0.05) ? (double)sz / dt / 1e6 : 0;
}

static int cmp(const void *a, const void *b) {
    const Item *x = a, *y = b;
    if (x->ok != y->ok) return y->ok - x->ok;
    return x->ms < y->ms ? -1 : x->ms > y->ms;
}
static int cmp_speed(const void *a, const void *b) {
    const Item *x = a, *y = b;
    if (x->mbps != y->mbps) return x->mbps < y->mbps ? 1 : -1;
    return cmp(a, b);
}
static int pass(const Item *it, double maxloss, int minms, int maxms) {
    double loss = (double)(it->tries - it->ok) / it->tries;
    return it->ok > 0 && loss <= maxloss && it->ms >= minms && it->ms <= maxms;
}

/* ---------- JSON / Base64 ---------- */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char *b64enc(const char *s, size_t n) {
    char *o = malloc(n / 3 * 4 + 8), *p = o; if (!o) return NULL;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)(unsigned char)s[i] << 16 | (i + 1 < n ? (uint32_t)(unsigned char)s[i + 1] << 8 : 0) | (i + 2 < n ? (uint32_t)(unsigned char)s[i + 2] : 0);
        *p++ = B64[v >> 18]; *p++ = B64[(v >> 12) & 63];
        *p++ = i + 1 < n ? B64[(v >> 6) & 63] : '='; *p++ = i + 2 < n ? B64[v & 63] : '=';
    }
    *p = 0; return o;
}
static char *b64dec(const char *s, size_t *len) {
    char *o = malloc(strlen(s) / 4 * 3 + 4), *p = o; if (!o) return NULL;
    uint32_t v = 0; int bits = 0;
    for (; *s; s++) {
        const char *q = strchr(B64, *s); if (!q) continue;
        v = v << 6 | (uint32_t)(q - B64); bits += 6;
        if (bits >= 8) { bits -= 8; *p++ = (char)((v >> bits) & 255); }
    }
    *p = 0; *len = (size_t)(p - o); return o;
}
static char *b64wrap(const char *s) {                /* 邮件正文：每 76 字符换行 */
    char *e = b64enc(s, strlen(s)); if (!e) return NULL;
    size_t n = strlen(e); char *o = malloc(n + n / 76 * 2 + 8), *p = o; if (!o) { free(e); return NULL; }
    for (size_t i = 0; i < n; i += 76) { size_t k = n - i < 76 ? n - i : 76; memcpy(p, e + i, k); p += k; *p++ = '\r'; *p++ = '\n'; }
    *p = 0; free(e); return o;
}
static char *json_dup(const char *j, const char *key) {   /* 取字符串字段，兼容 "key": "value" */
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(j, pat); if (!p) return NULL;
    p += strlen(pat); while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return NULL;
    p++; char *o = malloc(strlen(p) + 1), *q = o; if (!o) return NULL;
    for (; *p && *p != '"'; p++) {
        if (*p == '\\') { p++; if (!*p) break; if (*p == 'n' || *p == 'r') continue; }
        *q++ = *p;
    }
    *q = 0; return o;
}

/* ---------- 通知：Telegram / SMTP 邮件 ---------- */
static int tg_send(const char *tk, const char *chat, const char *msg) {
    CURL *cu = curl_easy_init(); if (!cu) return -1;
    ca(cu); direct(cu);
    char *e = curl_easy_escape(cu, msg, 0), *ch = curl_easy_escape(cu, chat, 0); int rc = -1;
    if (e && ch) {
        size_t L = strlen(e) + strlen(ch) + 32; char *b = malloc(L), url[300];
        if (b) {
            snprintf(b, L, "chat_id=%s&text=%s", ch, e); snprintf(url, sizeof url, "https://api.telegram.org/bot%s/sendMessage", tk);
            curl_easy_setopt(cu, CURLOPT_URL, url); curl_easy_setopt(cu, CURLOPT_POSTFIELDS, b);
            curl_easy_setopt(cu, CURLOPT_WRITEFUNCTION, nowrite); curl_easy_setopt(cu, CURLOPT_TIMEOUT, 20L);
            long st = 0; if (curl_easy_perform(cu) == CURLE_OK) curl_easy_getinfo(cu, CURLINFO_RESPONSE_CODE, &st);
            rc = (st >= 200 && st < 300) ? 0 : -1; free(b);
        }
    }
    curl_free(e); curl_free(ch); curl_easy_cleanup(cu); return rc;
}
static int send_mail(const char *host, int port, const char *user, const char *pass, const char *to, const char *subj, const char *body) {
    if (!has_proto(port == 465 ? "smtps" : "smtp")) return -1;
    struct curl_slist *rcpt = NULL; char toh[400] = "", *cp = strdup(to), *sp = NULL; if (!cp) return -1;
    for (char *t = strtok_r(cp, ",; \t", &sp); t; t = strtok_r(NULL, ",; \t", &sp)) {
        if (!mail_ok(t)) continue;
        char a[200]; snprintf(a, sizeof a, "<%s>", t); rcpt = curl_slist_append(rcpt, a);
        size_t L = strlen(toh); snprintf(toh + L, sizeof toh - L, "%s%s", L ? ", " : "", t);
    }
    free(cp); if (!rcpt) return -1;
    char *sb = b64enc(subj, strlen(subj)), *bb = b64wrap(body); int rc = -1;
    if (sb && bb) {
        size_t cap = strlen(bb) + strlen(sb) + 1024; char *pl = malloc(cap), date[64], url[300], from[220];
        if (pl) {
            time_t now = time(NULL); struct tm lt; localtime_r(&now, &lt); strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S %z", &lt);
            snprintf(pl, cap, "Date: %s\r\nFrom: <%s>\r\nTo: %s\r\nSubject: =?UTF-8?B?%s?=\r\nMIME-Version: 1.0\r\n"
                              "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n%s", date, user, toh, sb, bb);
            Src src = { pl, strlen(pl), 0 }; CURL *c = curl_easy_init();
            if (c) {
                ca(c); direct(c); snprintf(url, sizeof url, "%s://%s:%d", port == 465 ? "smtps" : "smtp", host, port); snprintf(from, sizeof from, "<%s>", user);
                curl_easy_setopt(c, CURLOPT_URL, url); curl_easy_setopt(c, CURLOPT_USERNAME, user); curl_easy_setopt(c, CURLOPT_PASSWORD, pass);
                curl_easy_setopt(c, CURLOPT_MAIL_FROM, from); curl_easy_setopt(c, CURLOPT_MAIL_RCPT, rcpt);
                curl_easy_setopt(c, CURLOPT_READFUNCTION, rcb); curl_easy_setopt(c, CURLOPT_READDATA, &src); curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
                curl_easy_setopt(c, CURLOPT_TIMEOUT, 40L);
                if (port != 465) curl_easy_setopt(c, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);   /* 587 等端口走 STARTTLS */
                rc = curl_easy_perform(c) == CURLE_OK ? 0 : -1; curl_easy_cleanup(c);
            }
            free(pl);
        }
    }
    free(sb); free(bb); curl_slist_free_all(rcpt); return rc;
}
/* 返回成功发送的通道数；Token + ID 或 SMTP 信息填全即自动启用 */
static int notify(const char *c, const char *msg) {
    int sent = 0; char tk[160], chat[64];
    getv(c, "tg_token", tk, sizeof tk); form_get(c, "tg_chat", chat, sizeof chat);
    if (tk[0] && chat[0] && !strpbrk(tk, "/ \r\n") && !tg_send(tk, chat, msg)) sent++;
    char host[96], user[120], pass[160], to[240]; int port = form_int(c, "mail_port", 465, 1, 65535);
    form_get(c, "mail_host", host, sizeof host); form_get(c, "mail_user", user, sizeof user);
    getv(c, "mail_pass", pass, sizeof pass); form_get(c, "mail_to", to, sizeof to);
    if (host_ok(host) && mail_ok(user) && pass[0] && to[0] && !send_mail(host, port, user, pass, to, "CF 优选通知", msg)) sent++;
    return sent;
}
static void summary(char *o, size_t n) {              /* 状态 + 前 10 个优选结果 + 下载链接 */
    pthread_mutex_lock(&mu);
    size_t L = (size_t)snprintf(o, n, "%s CF 优选：%s\n优选结果 %d 个\n", nres ? "✅" : "⚠️", phase, nres);
    for (int i = 0; i < nres && i < 10 && L < n - 500; i++) {
        char e[330], sp[40] = ""; fmt_entry(&res[i], "", e, sizeof e);
        if (res[i].mbps > 0) snprintf(sp, sizeof sp, "  %.1f MB/s", res[i].mbps);
        L += (size_t)snprintf(o + L, n - L, "%s  %.0f ms%s\n", e, res[i].ms, sp);
    }
    if (notes[0] && L < n - 400) L += (size_t)snprintf(o + L, n - L, "⚠️ 疑似开启代理 / VPN（%s），结果可能有误\n", notes);
    if (links[0] && L < n - 300) snprintf(o + L, n - L, "下载链接：\n%s", links);
    pthread_mutex_unlock(&mu);
}

/* ---------- 本地文件：待上传内容（stage）与手动编辑草稿（manual） ---------- */
static char *read_text(const char *path) {
    FILE *f = fopen(path, "r"); if (!f) return NULL;
    char *b = malloc(BODY_MAX + 1); if (!b) { fclose(f); return NULL; }
    size_t r = fread(b, 1, BODY_MAX, f); b[r] = 0; fclose(f); return b;
}
static int write_text(const char *path, const char *text) {   /* 先写临时文件再改名，避免写一半断电 */
    char tmp[340]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w"); if (!f) return -1;
    int ok = fputs(text, f) >= 0; ok = (fclose(f) == 0) && ok;
    if (!ok || rename(tmp, path)) { remove(tmp); return -1; }
    return 0;
}
static void spath(char *o, size_t n, const char *dir, const char *tag, const char *name, const char *ext) { snprintf(o, n, "data/%s/%s__%s%s", dir, tag, name, ext); }

/* ---------- 条目列表（IP / 域名[:端口][#后缀]） ---------- */
static int parse_list(const char *text, Item *out, int cap, int keep) {   /* 逐行解析，忽略无法识别的行，同 host:port 去重 */
    int n = 0; char *cp = text ? strdup(text) : NULL, *sp = NULL;
    for (char *l = cp ? strtok_r(cp, "\r\n", &sp) : NULL; l && n < cap; l = strtok_r(NULL, "\r\n", &sp)) {
        Item t; if (!parse_entry(l, &t)) continue;
        t.keep = keep;
        int dup = 0; for (int k = 0; k < n; k++) if (out[k].port == t.port && !strcmp(out[k].host, t.host)) { dup = 1; break; }
        if (!dup) out[n++] = t;
    }
    free(cp); return n;
}
static int in_list(const Item *a, int n, const Item *x) { for (int i = 0; i < n; i++) if (a[i].port == x->port && !strcmp(a[i].host, x->host)) return 1; return 0; }
static int line_in(const Item *a, int n, const Item *x) { for (int i = 0; i < n; i++) if (a[i].port == x->port && !strcmp(a[i].host, x->host) && !strcmp(a[i].suf, x->suf)) return 1; return 0; }

typedef struct { char *d; size_t n, cap; } SB;       /* 简单的字符串拼接器，用来拼 JSON */
static void sb_cat(SB *b, const char *s) {
    size_t l = strlen(s);
    if (b->n + l + 1 > b->cap) { size_t nc = (b->n + l + 1) * 2; char *nd = realloc(b->d, nc); if (!nd) return; b->d = nd; b->cap = nc; }
    memcpy(b->d + b->n, s, l + 1); b->n += l;
}
static void sb_json(SB *b, const char *s) {          /* 追加 JSON 转义后的文本 */
    char buf[512]; size_t k = 0;
    for (; *s; s++) {
        if (k + 8 > sizeof buf) { buf[k] = 0; sb_cat(b, buf); k = 0; }
        if (*s == '"' || *s == '\\') { buf[k++] = '\\'; buf[k++] = *s; }
        else if (*s == '\n') { buf[k++] = '\\'; buf[k++] = 'n'; }
        else if ((unsigned char)*s >= 32) buf[k++] = *s;
    }
    buf[k] = 0; sb_cat(b, buf);
}

static int parse_rule(char *ln, Rule *r) {            /* 一行：文件名|后缀|个数；后缀可省略 #，可含中文 / emoji */
    char *p = ln, *nm = strsep(&p, "|"), *sf = strsep(&p, "|"); if (!sf) sf = "";
    memset(r, 0, sizeof *r); r->cnt = p ? atoi(p) : 0;
    if (!safe(nm) || strlen(nm) >= sizeof r->name) return 0;
    snprintf(r->name, sizeof r->name, "%s", nm);
    while (*sf == ' ') sf++;
    if (*sf) {
        if (strlen(sf) > 60 || !suf_ok(sf)) return 0;
        snprintf(r->suf, sizeof r->suf, "%s%s", *sf == '#' ? "" : "#", sf);
    }
    return 1;
}
/* cnt<=0 写入全部；少于总数时按 cursor 轮询，依次给每个文件分配不同的条目 */
static char *render(Item *m, int n, int *cursor, const Rule *r) {
    int take = (r->cnt > 0 && r->cnt < n) ? r->cnt : n; char *o = malloc((size_t)take * 340 + 1); if (!o) return NULL;
    size_t L = 0;
    for (int k = 0; k < take; k++) { char e[330]; fmt_entry(&m[(*cursor + k) % n], r->suf, e, sizeof e); L += (size_t)snprintf(o + L, 340, "%s\n", e); }
    o[L] = 0; *cursor = (*cursor + take) % n; return o;
}

/* ---------- 上传目标：GitHub（REST API）/ SFTP（libcurl） ---------- */
typedef struct {
    int kind;                                         /* 1 GitHub / 2 SFTP */
    char tag[3], user[64], repo[64], tk[200], gtk[200], br[64];
    char host[96], pw[160], dir[200], base[200], files[2048];
} Tgt;
static void trim(char *s) {
    char *p = s; while (isspace((unsigned char)*p)) p++;
    memmove(s, p, strlen(p) + 1);
    for (size_t n = strlen(s); n && isspace((unsigned char)s[n - 1]);) s[--n] = 0;
}
static int norm_dir(char *d) {                        /* \ 换成 /，合并重复斜杠，去掉末尾斜杠；含 .. 或控制字符返回 0 */
    char *w = d; int prev = 0;
    for (char *r = d; *r; r++) {
        char ch = *r == '\\' ? '/' : *r;
        if ((unsigned char)ch < 32 || ch == 127) return 0;
        if (ch == '/' && prev) continue;
        *w++ = ch; prev = ch == '/';
    }
    *w = 0; size_t n = strlen(d); while (n > 1 && d[n - 1] == '/') d[--n] = 0;
    return !strstr(d, "..");
}
static void enc_path(const char *s, char *o, size_t n) {
    size_t k = 0;
    for (; *s && k + 4 < n; s++) {
        if (isalnum((unsigned char)*s) || strchr("/._-~", *s)) o[k++] = *s;
        else k += (size_t)snprintf(o + k, n - k, "%%%02X", (unsigned char)*s);
    }
    o[k] = 0;
}
/* 返回：0 未填写 / 1 可用 / -1 内容不合法（原因已写入 phase） */
static int tgt_init(Tgt *t, int kind, const char *c) {
    memset(t, 0, sizeof *t); t->kind = kind; snprintf(t->tag, sizeof t->tag, "%s", kind == 1 ? "gh" : "sf"); snprintf(t->br, sizeof t->br, "main");
    char msg[300];
    if (kind == 1) {
        form_get(c, "gh_user", t->user, sizeof t->user); form_get(c, "gh_repo", t->repo, sizeof t->repo);
        getv(c, "gh_token", t->tk, sizeof t->tk); getv(c, "gh_git_token", t->gtk, sizeof t->gtk);
        form_get(c, "gh_files", t->files, sizeof t->files);
        trim(t->user); trim(t->repo); trim(t->tk); trim(t->gtk);
        if (!t->gtk[0]) snprintf(t->gtk, sizeof t->gtk, "%s", t->tk);           /* 没单独填 git 用 PAT 就复用 API 的 PAT */
        if (!t->user[0] || !t->repo[0] || !t->tk[0] || !t->files[0]) return 0;
        if (!safe(t->user) || !safe(t->repo) || strpbrk(t->tk, "\r\n \t") || strpbrk(t->gtk, "\r\n \t")) { setphase("GitHub 用户名 / 仓库名 / PAT 含非法字符（用户名和仓库名只能含字母数字 . _ -）"); return -1; }
        return 1;
    }
    form_get(c, "sf_host", t->host, sizeof t->host); form_get(c, "sf_user", t->user, sizeof t->user);
    getv(c, "sf_pass", t->pw, sizeof t->pw); form_get(c, "sf_dir", t->dir, sizeof t->dir);
    form_get(c, "sf_base", t->base, sizeof t->base); form_get(c, "sf_files", t->files, sizeof t->files);
    trim(t->host); trim(t->user); trim(t->dir); trim(t->base);
    if (!strncmp(t->host, "sftp://", 7)) memmove(t->host, t->host + 7, strlen(t->host + 7) + 1);
    if (!t->host[0] || !t->user[0] || !t->pw[0] || !t->files[0]) return 0;
    for (const char *q = t->host; *q; q++)
        if (!isalnum((unsigned char)*q) && !strchr(".-_:", *q)) {
            snprintf(msg, sizeof msg, "SFTP「服务器地址」含不允许的字符（第 %d 个字符，编码 0x%02X）：「%s」。只能含字母、数字和 . - _ :，不要带 sftp:// 和路径",
                     (int)(q - t->host) + 1, (unsigned char)*q, t->host);
            setphase(msg); return -1;
        }
    if (!norm_dir(t->dir)) { snprintf(msg, sizeof msg, "SFTP「服务器文件路径」不合法：「%s」（不能含 .. 或控制字符）", t->dir); setphase(msg); return -1; }
    if (strncmp(t->base, "https://", 8)) t->base[0] = 0;
    return 1;
}
static const char *tgt_name(const Tgt *t) { return t->kind == 1 ? "GitHub" : "SFTP"; }
static void sftp_url(const Tgt *t, const char *name, char *o, size_t n) {   /* 双斜杠 = 服务器绝对路径；不以 / 开头 = 相对登录目录 */
    char e[700]; enc_path(t->dir, e, sizeof e);
    if (!t->dir[0]) snprintf(o, n, "sftp://%s/%s", t->host, name);
    else if (!strcmp(t->dir, "/")) snprintf(o, n, "sftp://%s//%s", t->host, name);
    else snprintf(o, n, "sftp://%s/%s/%s", t->host, e, name);
}
static void addlink(const char *u) {
    pthread_mutex_lock(&mu);
    if (!strstr(links, u)) { size_t L = strlen(links); snprintf(links + L, sizeof links - L, "%s\n", u); }
    pthread_mutex_unlock(&mu);
}
static void tgt_link(const Tgt *t, const char *name) {
    char u[700];
    if (t->kind == 1) snprintf(u, sizeof u, "https://raw.githubusercontent.com/%s/%s/refs/heads/%s/%s", t->user, t->repo, t->br, name);
    else if (t->base[0]) snprintf(u, sizeof u, "%s%s%s", t->base, t->base[strlen(t->base) - 1] == '/' ? "" : "/", name);
    else return;
    addlink(u);
}

/* GitHub API：连接超时 10 秒；失败自动重试 3 次（第 2 次只用 IPv4，第 3 次改用 HTTP/1.1）；失败原因写入 ferr */
static long ghreq(const char *method, const char *url, const char *tk, const char *body, char **out) {
    long st = 0; if (out) *out = NULL; ferr[0] = 0;
    for (int at = 0; at < 3; at++) {
        Buf b = { 0 }; CURL *c = curl_easy_init();
        if (!c) { snprintf(ferr, sizeof ferr, "curl 初始化失败"); return 0; }
        ca(c); direct(c);
        struct curl_slist *h = NULL; char t[300];
        snprintf(t, sizeof t, "Authorization: Bearer %s", tk); h = curl_slist_append(h, t);
        h = curl_slist_append(h, "Accept: application/vnd.github+json"); h = curl_slist_append(h, "X-GitHub-Api-Version: 2022-11-28");
        if (body) h = curl_slist_append(h, "Content-Type: application/json");
        curl_easy_setopt(c, CURLOPT_URL, url); curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method);
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, h); curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L); curl_easy_setopt(c, CURLOPT_TIMEOUT, 40L);
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wcb); curl_easy_setopt(c, CURLOPT_WRITEDATA, &b);
        if (body) curl_easy_setopt(c, CURLOPT_POSTFIELDS, body); else curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
        if (at >= 1) curl_easy_setopt(c, CURLOPT_IPRESOLVE, (long)CURL_IPRESOLVE_V4);
        if (at >= 2) curl_easy_setopt(c, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
        CURLcode rc = curl_easy_perform(c); st = 0;
        if (rc == CURLE_OK) curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &st); else snprintf(ferr, sizeof ferr, "%s", curl_easy_strerror(rc));
        curl_slist_free_all(h); curl_easy_cleanup(c);
        int retry = rc != CURLE_OK || st == 429 || st >= 500 || (st == 403 && b.d && strstr(b.d, "rate limit"));
        if (!retry || at == 2) {
            if (rc == CURLE_OK && st >= 400) { char *mg = b.d ? json_dup(b.d, "message") : NULL; snprintf(ferr, sizeof ferr, "HTTP %ld %s", st, mg ? mg : ""); free(mg); }
            if (out) *out = b.d; else free(b.d);
            return st;
        }
        free(b.d); sleep((unsigned)(1 << at));
    }
    return st;
}
static CURL *sftp_open(const char *url, const char *user, const char *pw) {
    CURL *c = curl_easy_init(); if (!c) return NULL;
    ca(c); direct(c); curl_easy_setopt(c, CURLOPT_URL, url); curl_easy_setopt(c, CURLOPT_USERNAME, user);
    curl_easy_setopt(c, CURLOPT_PASSWORD, pw); curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L); curl_easy_setopt(c, CURLOPT_TIMEOUT, 40L);
    return c;
}
/* ---------- git 备用通道：GitHub API 失败时改用 git 读写（token 写入 data/gitcred，命令行里不出现 token） ---------- */
static __thread int gh_api_down;                      /* 本次操作里 API 已确认不可用，直接走 git */
static __thread char gh_apierr[400];                  /* 预检时记下的 API 失败原因 */
static int have_git(void) { static int v = -1; if (v < 0) v = system("git --version >/dev/null 2>&1") == 0; return v; }
static int git_cmd(const char *fmt, ...) {
    char args[1000], cmd[2600]; va_list ap;
    if (!wd[0] && !getcwd(wd, sizeof wd)) return 0;
    if (strlen(wd) > 1000) { snprintf(ferr, sizeof ferr, "数据目录路径过长，无法使用 git 备用通道"); return 0; }
    va_start(ap, fmt); vsnprintf(args, sizeof args, fmt, ap); va_end(ap);
    snprintf(cmd, sizeof cmd, "git -c credential.helper= -c credential.helper='store --file=%s/data/gitcred' -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=30 %s >/dev/null 2>'%s/data/git.err'", wd, args, wd);
    int rc = system(cmd);
    if (rc) {
        char *e = read_text("data/git.err");
        if (e) { for (char *p = e; *p; p++) if (*p == '\n' || *p == '\r') *p = ' '; trim(e); snprintf(ferr, sizeof ferr, "%.300s", e); free(e); }
    }
    return rc == 0;
}
static int git_sync(const Tgt *t, char *dir, size_t dn, int *empty) {     /* 克隆或更新到最新；空仓库时 *empty=1 */
    char cu[300], ct[600], line[1000], gd[4400]; int fresh;
    *empty = 0;
    if (!have_git()) { snprintf(ferr, sizeof ferr, "本机没有安装 git"); return 0; }
    if (!t->gtk[0]) { snprintf(ferr, sizeof ferr, "未填写 git 用 PAT"); return 0; }
    if (!wd[0] && !getcwd(wd, sizeof wd)) { snprintf(ferr, sizeof ferr, "无法确定数据目录"); return 0; }
    snprintf(dir, dn, "%s/data/git/%s__%s", wd, t->user, t->repo);
    if (strchr(dir, '\'')) { snprintf(ferr, sizeof ferr, "数据目录路径含单引号，无法使用 git 备用通道"); return 0; }
    urlenc(t->user, cu, sizeof cu); urlenc(t->gtk, ct, sizeof ct);
    snprintf(line, sizeof line, "https://%s:%s@github.com\n", cu, ct);
    mkdir("data", 0700); mkdir("data/git", 0700);
    if (write_text("data/gitcred", line)) { snprintf(ferr, sizeof ferr, "无法写入 data/gitcred"); return 0; }
    chmod("data/gitcred", 0600);
    snprintf(gd, sizeof gd, "%s/.git", dir); fresh = access(gd, R_OK) != 0;
    if (fresh) {
        sh("rm -rf '%s'", dir);                       /* 清掉上次中断留下的半成品目录 */
        if (!git_cmd("clone -q --depth 1 https://github.com/%s/%s.git '%s'", t->user, t->repo, dir)) return 0;
        if (!git_cmd("-C '%s' rev-parse --verify -q HEAD", dir)) *empty = 1;
    } else if (git_cmd("-C '%s' fetch -q --depth 1 origin HEAD", dir)) {
        if (!git_cmd("-C '%s' reset -q --hard FETCH_HEAD", dir)) return 0;
    } else {
        if (git_cmd("-C '%s' rev-parse --verify -q HEAD", dir)) return 0;      /* 有本地提交但 fetch 失败：网络问题 */
        *empty = 1;                                                          /* 没有任何提交：远端是空仓库 */
    }
    return 1;
}
static int git_get(const Tgt *t, const char *name, char **text) {
    char dir[4300], p[4500]; int empty; *text = NULL;
    if (!git_sync(t, dir, sizeof dir, &empty)) return 0;
    snprintf(p, sizeof p, "%s/%s", dir, name); *text = read_text(p); return 1;
}
static int git_put(const Tgt *t, const char *name, const char *txt) {
    char dir[4300], p[4500]; int empty;
    if (!git_sync(t, dir, sizeof dir, &empty)) return 0;
    snprintf(p, sizeof p, "%s/%s", dir, name);
    if (write_text(p, txt)) { snprintf(ferr, sizeof ferr, "无法写入本地仓库文件"); return 0; }
    if (!git_cmd("-C '%s' add -- '%s'", dir, name)) return 0;
    if (git_cmd("-C '%s' diff --cached --quiet", dir)) return 1;              /* 没有变化，无需提交 */
    if (!git_cmd("-C '%s' -c user.name=cfip -c user.email=cfip@users.noreply.github.com commit -q -m 'update ips'", dir)) return 0;
    return git_cmd("-C '%s' push -q origin HEAD", dir);
}
static int git_ok(const Tgt *t) { return t->kind == 1 && t->gtk[0] && have_git(); }

/* 读取远端文件。返回 1 成功（*text 为 NULL 表示文件不存在）/ 0 失败（原因在 ferr，此时绝不能当作“文件不存在”去覆盖） */
static int tgt_get(const Tgt *t, const char *name, char **text, char **sha) {
    *text = NULL; if (sha) *sha = NULL; ferr[0] = 0;
    if (t->kind == 1) {
        char url[600], *j = NULL, ae[400] = "", ge[400]; long st = 0;
        if (gh_api_down) snprintf(ae, sizeof ae, "%s", gh_apierr);
        else {
            snprintf(url, sizeof url, "https://api.github.com/repos/%s/%s/contents/%s", t->user, t->repo, name);
            st = ghreq("GET", url, t->tk, NULL, &j);
            if (st == 200 && j) {
                if (sha) *sha = json_dup(j, "sha");
                char *cb = json_dup(j, "content"); size_t L;
                *text = cb ? b64dec(cb, &L) : strdup(""); free(cb); free(j); return 1;
            }
            free(j); if (st == 404) return 1;
            snprintf(ae, sizeof ae, "%s", ferr);
        }
        if (git_ok(t)) {                              /* API 不通：改用 git 读取 */
            gh_api_down = 1; setphase("GitHub API 读取失败，改用 git 通道读取");
            if (git_get(t, name, text)) return 1;
            snprintf(ge, sizeof ge, "%s", ferr); snprintf(ferr, sizeof ferr, "API %.180s；git %.180s", ae, ge);
        }
        return 0;
    }
    char url[1000]; sftp_url(t, name, url, sizeof url);
    for (int at = 0; at < 2; at++) {
        Buf b = { 0 }; CURL *cu = sftp_open(url, t->user, t->pw);
        if (!cu) { snprintf(ferr, sizeof ferr, "curl 初始化失败"); return 0; }
        curl_easy_setopt(cu, CURLOPT_WRITEFUNCTION, wcb); curl_easy_setopt(cu, CURLOPT_WRITEDATA, &b);
        CURLcode rc = curl_easy_perform(cu); curl_easy_cleanup(cu);
        if (rc == CURLE_OK) { *text = b.d ? b.d : strdup(""); return 1; }
        free(b.d);
        if (rc == CURLE_REMOTE_FILE_NOT_FOUND) return 1;
        snprintf(ferr, sizeof ferr, "%s", curl_easy_strerror(rc));
        if (rc == CURLE_LOGIN_DENIED) return 0;
        sleep(1);
    }
    return 0;
}
static int tgt_put(const Tgt *t, const char *name, const char *txt, const char *sha) {
    ferr[0] = 0;
    if (t->kind == 1) {
        char url[600]; snprintf(url, sizeof url, "https://api.github.com/repos/%s/%s/contents/%s", t->user, t->repo, name);
        char *cur = sha ? strdup(sha) : NULL, ae[400] = "", ge[400]; int ok = 0;
        if (gh_api_down) snprintf(ae, sizeof ae, "%s", gh_apierr);
        for (int at = 0; at < 2 && !ok && !gh_api_down; at++) {
            char *e = b64enc(txt, strlen(txt)); if (!e) break;
            size_t L = strlen(e) + 200; char *body = malloc(L); if (!body) { free(e); break; }
            snprintf(body, L, "{\"message\":\"update ips\",\"content\":\"%s\"%s%s%s}", e, cur ? ",\"sha\":\"" : "", cur ? cur : "", cur ? "\"" : "");
            free(e); long st = ghreq("PUT", url, t->tk, body, NULL); free(body);
            if (st == 200 || st == 201) { ok = 1; break; }
            if ((st == 409 || st == 422) && at == 0) {          /* 文件在读取之后又变了：刷新 sha 重试一次 */
                char *tx = NULL, *ns = NULL;
                if (tgt_get(t, name, &tx, &ns)) { free(tx); free(cur); cur = ns; continue; }
                free(tx); free(ns);
            }
            break;
        }
        free(cur);
        if (ok) return 1;
        if (!gh_api_down) snprintf(ae, sizeof ae, "%s", ferr);
        if (git_ok(t)) {                              /* API 写入失败：改用 git 提交并推送 */
            gh_api_down = 1; setphase("GitHub API 上传失败，改用 git 通道上传");
            if (git_put(t, name, txt)) return 1;
            snprintf(ge, sizeof ge, "%s", ferr); snprintf(ferr, sizeof ferr, "API %.180s；git %.180s", ae, ge);
        }
        return 0;
    }
    char url[1000]; sftp_url(t, name, url, sizeof url);
    for (int at = 0; at < 2; at++) {
        Src s = { txt, strlen(txt), 0 }; CURL *cu = sftp_open(url, t->user, t->pw);
        if (!cu) { snprintf(ferr, sizeof ferr, "curl 初始化失败"); return 0; }
        curl_easy_setopt(cu, CURLOPT_UPLOAD, 1L); curl_easy_setopt(cu, CURLOPT_READFUNCTION, rcb);
        curl_easy_setopt(cu, CURLOPT_READDATA, &s); curl_easy_setopt(cu, CURLOPT_INFILESIZE_LARGE, (curl_off_t)s.n);
        curl_easy_setopt(cu, CURLOPT_FTP_CREATE_MISSING_DIRS, 1L);
        CURLcode rc = curl_easy_perform(cu); curl_easy_cleanup(cu);
        if (rc == CURLE_OK) return 1;
        snprintf(ferr, sizeof ferr, "%s", curl_easy_strerror(rc));
        if (rc == CURLE_LOGIN_DENIED) return 0;
        sleep(1);
    }
    return 0;
}

/* ---------- 单个文件：读取远端 → 复测 → 合并 → 上传 ----------
 * stage：已合并好、等待上传的内容（上传失败时保留）；manual：用户在「查看」里保存的草稿（.orig 是查看时的远端原文）。
 * 手动上传时，如果已有 stage（说明自动上传已经复测过远端旧条目），就不再复测，直接合并上传。 */
static int do_file(const Tgt *t, const Rule *r, int manual, Item *good, int ng, double ml, int mn, int mx, Item *m, int *cursor) {
    char stp[300], dp[300], op[300], msg[800];
    spath(stp, sizeof stp, "stage", t->tag, r->name, ""); spath(dp, sizeof dp, "manual", t->tag, r->name, ".txt"); spath(op, sizeof op, "manual", t->tag, r->name, ".orig");
    char *stage = read_text(stp), *draft = read_text(dp), *orig = read_text(op), *rtext = NULL, *sha = NULL, *txt = NULL;
    Item *D = calloc(MAXIP, sizeof *D), *B = calloc(MAXIP, sizeof *B), *tru = calloc(MAXIP, sizeof *tru), *rem = calloc(MAXIP, sizeof *rem);
    int rc = -1, nd = 0, nb = 0, nt = 0, nr = 0, n = 0, staged_mode, retest;
    if (!D || !B || !tru || !rem) { setphase("内存不足"); goto out; }

    staged_mode = draft ? (!orig && stage != NULL) : (stage != NULL);
    if (draft) {                                     /* 草稿 = 用户编辑后的完整文本；与查看时的原文比较，得出新增 / 删除 */
        nd = parse_list(draft, D, MAXIP, 0); nb = parse_list(orig ? orig : stage, B, MAXIP, 0);
        for (int i = 0; i < nd && nt < MAXIP; i++) {
            int fresh = !line_in(B, nb, &D[i]);      /* 新增或改过的行：原样保留（含后缀）；没改的行按文件后缀规则 */
            if (staged_mode || fresh) { tru[nt] = D[i]; tru[nt].keep = fresh; nt++; }
        }
    } else if (stage) nt = parse_list(stage, tru, MAXIP, 0);

    retest = !manual || !staged_mode;
    if (retest || t->kind == 1) {                    /* GitHub 即使不复测也要取一次 sha */
        setphase(retest ? "读取远端旧文件" : "读取远端文件信息");
        if (!tgt_get(t, r->name, &rtext, &sha)) {
            snprintf(msg, sizeof msg, "%s 读取失败：%s。可稍后在结果区点「%s 上传」重试", tgt_name(t), ferr, tgt_name(t)); setphase(msg); goto out;
        }
    }
    if (retest) {
        nr = parse_list(rtext, rem, MAXIP, 0);
        if (draft) { int k = 0; for (int i = 0; i < nr; i++) if (line_in(D, nd, &rem[i]) || !line_in(B, nb, &rem[i])) rem[k++] = rem[i]; nr = k; }   /* 去掉用户删除的行 */
        if (nr) {
            setphase("复测远端旧条目"); prog(nr); run_pool(rem, nr);
            int k = 0; for (int i = 0; i < nr; i++) if (pass(&rem[i], ml, mn, mx)) rem[k++] = rem[i];
            nr = k;
        }
    }
    for (int i = 0; i < nt && n < MAXIP * 2; i++) if (!in_list(m, n, &tru[i])) m[n++] = tru[i];     /* 先放手动 / 待上传的条目 */
    for (int i = 0; i < ng && nr < MAXIP; i++) {     /* 再并入新筛选结果（用户删掉的除外） */
        if (draft && in_list(B, nb, &good[i]) && !in_list(D, nd, &good[i])) continue;
        if (!in_list(rem, nr, &good[i])) rem[nr++] = good[i];
    }
    qsort(rem, (size_t)nr, sizeof *rem, cmp);
    for (int i = 0; i < nr && n < MAXIP * 2; i++) if (!in_list(m, n, &rem[i])) m[n++] = rem[i];

    if (!n) { if (manual) setphase("没有可上传的内容：没有待上传的结果，远端也没有可保留的条目"); rc = 0; goto out; }
    txt = render(m, n, cursor, r);
    if (!txt) { setphase("内存不足"); goto out; }
    write_text(stp, txt); remove(dp); remove(op);    /* 先落盘为“待上传内容”，草稿已并入其中 */
    setphase(t->kind == 1 ? "上传到 GitHub" : "上传到 SFTP");
    if (!tgt_put(t, r->name, txt, sha)) {
        snprintf(msg, sizeof msg, "%s 上传失败：%s。已保留待上传内容，可在结果区点「%s 上传」重试", tgt_name(t), ferr, tgt_name(t)); setphase(msg); goto out;
    }
    remove(stp); tgt_link(t, r->name); rc = 1;
out:
    free(stage); free(draft); free(orig); free(rtext); free(sha); free(txt); free(D); free(B); free(tru); free(rem);
    return rc;
}

/* 返回：0 未填写 / 1 已上传 / 2 完成但有警告 / 3 没有需要上传的内容 / -1 失败（原因在 phase） */
static int upload_target(const char *c, int kind, Item *good, int ng, double ml, int mn, int mx, int manual) {
    Tgt t; int ti = tgt_init(&t, kind, c); if (ti <= 0) return ti;
    gh_api_down = 0; gh_apierr[0] = 0;
    if (kind == 1) {                                 /* 取默认分支（用于下载链接）；API 不通时若有 git 就改走 git，否则按原因报错 */
        char url[400], *j = NULL; setphase("连接 GitHub");
        snprintf(url, sizeof url, "https://api.github.com/repos/%s/%s", t.user, t.repo);
        long st = ghreq("GET", url, t.tk, NULL, &j);
        if (st == 200 && j) { char *d = json_dup(j, "default_branch"); if (d && d[0] && safe(d)) snprintf(t.br, sizeof t.br, "%s", d); free(d); }
        else if (git_ok(&t)) { gh_api_down = 1; snprintf(gh_apierr, sizeof gh_apierr, "%s", st ? "HTTP 状态异常" : ferr); if (st) snprintf(gh_apierr, sizeof gh_apierr, "HTTP %ld", st); }   /* 先用 git，不再白等 API 重试 */
        else if (st == 401) { free(j); setphase("GitHub 认证失败：请检查 PAT 是否正确、是否过期"); return -1; }
        else if (st == 404) { free(j); setphase("GitHub 找不到该仓库：请检查用户名、仓库名，以及 PAT 是否有该仓库的权限"); return -1; }
        free(j);
    }
    Item *m = calloc(MAXIP * 2, sizeof *m); if (!m) { setphase("内存不足"); return -1; }
    int cursor = 0, bad = 0, did = 0; char files[2048], *sp = NULL; snprintf(files, sizeof files, "%s", t.files);
    for (char *ln = strtok_r(files, "\r\n", &sp); ln; ln = strtok_r(NULL, "\r\n", &sp)) {
        Rule r; if (!parse_rule(ln, &r)) { bad = 1; continue; }
        int rc = do_file(&t, &r, manual, good, ng, ml, mn, mx, m, &cursor);
        if (rc < 0) { free(m); return -1; }
        if (rc > 0) did++;
    }
    free(m);
    if (bad) { setphase(kind == 1 ? "GitHub 已完成，部分文件名或后缀不合法已跳过（文件名只能含字母数字 . _ -，后缀不能含 |）" : "SFTP 已完成，部分文件名或后缀不合法已跳过（文件名只能含字母数字 . _ -，后缀不能含 |）"); return 2; }
    return did ? 1 : 3;
}
/* 自动上传：GitHub 和 SFTP 各自独立执行，一个失败不影响另一个；失败原因合并显示 */
static void upload_all(const char *c, Item *good, int ng, double ml, int mn, int mx) {
    char msg[2][700] = { "", "" }; int any = 0, bad = 0;
    for (int k = 1; k <= 2; k++) {
        int r = upload_target(c, k, good, ng, ml, mn, mx, 0);
        if (r < 0 || r == 2) { pthread_mutex_lock(&mu); snprintf(msg[k - 1], sizeof msg[0], "%s", phase); pthread_mutex_unlock(&mu); bad = 1; }
        if (r > 0) any = 1;
    }
    if (bad) { char o[1500]; snprintf(o, sizeof o, "%s%s%s", msg[0], msg[0][0] && msg[1][0] ? "｜" : "", msg[1]); setphase(o); }
    else setphase(any ? "全部完成" : "筛选完成：未填写上传信息，仅筛选不上传");
}

/* ---------- 「查看」与草稿 ---------- */
static char *view_target(const char *c, int kind, int reset) {   /* 返回 JSON：每个文件的当前内容及来源 */
    Tgt t; SB b = { 0 }; int ti = tgt_init(&t, kind, c);
    gh_api_down = 0;
    if (ti <= 0) {
        sb_cat(&b, "{\"ok\":0,\"msg\":\"");
        if (ti == 0) sb_json(&b, kind == 1 ? "请先填写 GitHub 用户名、仓库名、PAT 和文件名" : "请先填写 SFTP 服务器、用户名、密码和文件名");
        else { pthread_mutex_lock(&mu); sb_json(&b, phase); pthread_mutex_unlock(&mu); }
        sb_cat(&b, "\"}"); return b.d ? b.d : strdup("{\"ok\":0}");
    }
    sb_cat(&b, "{\"ok\":1,\"files\":["); int first = 1; char files[2048], *sp = NULL; snprintf(files, sizeof files, "%s", t.files);
    for (char *ln = strtok_r(files, "\r\n", &sp); ln; ln = strtok_r(NULL, "\r\n", &sp)) {
        Rule r; if (!parse_rule(ln, &r)) continue;
        char dp[300], op[300], stp[300]; spath(dp, sizeof dp, "manual", t.tag, r.name, ".txt"); spath(op, sizeof op, "manual", t.tag, r.name, ".orig"); spath(stp, sizeof stp, "stage", t.tag, r.name, "");
        if (reset) { remove(dp); remove(op); }
        char *draft = read_text(dp), *stage = read_text(stp), *rt = NULL, *sha = NULL; const char *src = "remote", *note = "", *show = "";
        if (draft) { src = "draft"; show = draft; }
        else if (stage) { src = "staged"; show = stage; remove(op); }
        else if (tgt_get(&t, r.name, &rt, &sha)) { show = rt ? rt : ""; src = rt ? "remote" : "new"; write_text(op, show); }   /* 记下原文，保存草稿时用来区分新增 / 删除 */
        else { src = "error"; note = ferr; }
        if (!first) sb_cat(&b, ",");
        first = 0;
        sb_cat(&b, "{\"name\":\""); sb_json(&b, r.name); sb_cat(&b, "\",\"src\":\""); sb_cat(&b, src);
        sb_cat(&b, "\",\"note\":\""); sb_json(&b, note); sb_cat(&b, "\",\"text\":\""); sb_json(&b, show); sb_cat(&b, "\"}");
        free(draft); free(stage); free(rt); free(sha);
    }
    sb_cat(&b, "]}"); return b.d ? b.d : strdup("{\"ok\":0}");
}
static int save_draft(const char *tag, const char *name, const char *text, char *msg, size_t mn) {
    if ((strcmp(tag, "gh") && strcmp(tag, "sf")) || !safe(name)) { snprintf(msg, mn, "参数不合法"); return 0; }
    Item *L = calloc(MAXIP, sizeof *L); if (!L) { snprintf(msg, mn, "内存不足"); return 0; }
    int n = parse_list(text, L, MAXIP, 0), lines = 0;
    { char *cp = strdup(text), *sp = NULL; for (char *l = cp ? strtok_r(cp, "\r\n", &sp) : NULL; l; l = strtok_r(NULL, "\r\n", &sp)) { while (isspace((unsigned char)*l)) l++; if (*l) lines++; } free(cp); }
    SB o = { 0 };
    for (int i = 0; i < n; i++) { char e[330]; L[i].keep = 1; fmt_entry(&L[i], "", e, sizeof e); sb_cat(&o, e); sb_cat(&o, "\n"); }   /* 规范化后保存 */
    free(L);
    char dp[300], op[300], stp[300]; spath(dp, sizeof dp, "manual", tag, name, ".txt"); spath(op, sizeof op, "manual", tag, name, ".orig"); spath(stp, sizeof stp, "stage", tag, name, "");
    char *stage = read_text(stp);
    if (stage) remove(op); else if (access(op, R_OK)) write_text(op, "");      /* 没有原文时按“全部是新增”处理 */
    free(stage);
    int rc = write_text(dp, o.d ? o.d : ""); free(o.d);
    if (rc) { snprintf(msg, mn, "保存失败：无法写入本地文件"); return 0; }
    snprintf(msg, mn, lines > n ? "已保存 %d 行草稿（另有 %d 行重复或无法识别，已忽略）" : "已保存 %d 行草稿", n, lines - n);
    return 1;
}

/* ---------- 最近一次筛选结果（供手动上传使用，重启后仍在）与参数解析 ---------- */
static void save_results(void) {
    pthread_mutex_lock(&mu);
    FILE *f = fopen("data/last_results.txt.tmp", "w");
    if (f) {
        for (int i = 0; i < nres; i++) fprintf(f, "%s %d %d %d %d %.3f %.3f\n", res[i].host, res[i].port, res[i].dom, res[i].ok, res[i].tries, res[i].ms, res[i].mbps);
        if (fclose(f) == 0) rename("data/last_results.txt.tmp", "data/last_results.txt");
    }
    pthread_mutex_unlock(&mu);
}
static int load_results(Item *out, int cap) {
    FILE *f = fopen("data/last_results.txt", "r"); if (!f) return 0;
    int n = 0;
    while (n < cap) {
        Item t; memset(&t, 0, sizeof t);
        if (fscanf(f, "%127s %d %d %d %d %lf %lf", t.host, &t.port, &t.dom, &t.ok, &t.tries, &t.ms, &t.mbps) != 7) break;
        if (t.port < 1 || t.port > 65535 || t.tries < 1) continue;
        out[n++] = t;
    }
    fclose(f); return n;
}
static char snibuf[1024];
static void parse_params(const char *c, double *maxloss, int *minms, int *maxms) {   /* 测速 / 复测共用的参数 */
    char s[64];
    P.port = form_int(c, "port", 443, 1, 65535); P.timeout = form_int(c, "timeout", 1500, 200, 10000);
    P.tries = form_int(c, "tries", 3, 1, 10); P.threads = form_int(c, "threads", 16, 1, 64);
    form_get(c, "sni", snibuf, sizeof snibuf); P.nsni = 0;
    { char *sp = NULL; for (char *t = strtok_r(snibuf, "\r\n ,;\t", &sp); t && P.nsni < 8; t = strtok_r(NULL, "\r\n ,;\t", &sp)) if (host_ok(t)) P.sni[P.nsni++] = t; }
    *minms = form_int(c, "minms", 0, 0, 9999); *maxms = form_int(c, "maxms", 9999, 1, 9999);
    form_get(c, "loss", s, sizeof s); *maxloss = s[0] ? atof(s) : 1.0;
}
static int count_pending(int kind) {                 /* 有多少个文件还有待上传内容（用于按钮提示） */
    char files[2048], *sp = NULL; int n = 0;
    pthread_mutex_lock(&mu); form_get(cfg, kind == 1 ? "gh_files" : "sf_files", files, sizeof files); pthread_mutex_unlock(&mu);
    for (char *ln = strtok_r(files, "\r\n", &sp); ln; ln = strtok_r(NULL, "\r\n", &sp)) {
        Rule r; char p[300]; if (!parse_rule(ln, &r)) continue;
        spath(p, sizeof p, "stage", kind == 1 ? "gh" : "sf", r.name, ""); if (!access(p, R_OK)) n++;
    }
    return n;
}

/* ---------- 任务 ---------- */
static void run_job(const char *c, Item *cand, char *buf) {
    char s[256], pwhy[200], dl_url[300]; int n = 0, minms, maxms; double maxloss;
    parse_params(c, &maxloss, &minms, &maxms);
    int samples = form_int(c, "samples", 3, 1, 20), nseg = form_int(c, "nseg", 10, 0, 500), ndom = form_int(c, "ndom", 20, 0, 500);
    int want = form_int(c, "count", 10, 1, 500);
    int dl_on = form_int(c, "dl_on", 0, 0, 1); DL.secs = form_int(c, "dl_secs", 6, 2, 30);
    form_get(c, "dl_min", s, sizeof s); double dl_min = s[0] ? atof(s) : 0;
    form_get(c, "dl_url", dl_url, sizeof dl_url);
    if (strncmp(dl_url, "https://", 8)) snprintf(dl_url, sizeof dl_url, "%s", "https://speed.cloudflare.com/__down?bytes=50000000");
    { const char *h = dl_url + 8, *e = h + strcspn(h, "/:?"); size_t hl = (size_t)(e - h);
      if (hl == 0 || hl >= sizeof DL.host) { dl_on = 0; } else { memcpy(DL.host, h, hl); DL.host[hl] = 0;
        const char *p = strchr(e, '/'); snprintf(DL.path, sizeof DL.path, "%s", p ? p : "/"); if (!host_ok(DL.host)) dl_on = 0; } }

    int sus = proxy_check(pwhy, sizeof pwhy);
    pthread_mutex_lock(&mu); snprintf(notes, sizeof notes, "%s", sus ? pwhy : ""); pthread_mutex_unlock(&mu);

    setphase("生成候选 IP / 域名");
    const char *en[3] = { "v4", "v6", "vd" }, *tx[3] = { "cidr4", "cidr6", "doms" }, *ur[3] = { "url4", "url6", "urld" };
    for (int i = 0; i < 3; i++) {
        if (!form_int(c, en[i], 0, 0, 1)) continue;
        form_get(c, tx[i], buf, REQ_MAX);
        if (!buf[0]) {                                /* 编辑框为空：先按 URL 拉取，IPv4/IPv6 再回退到内置官方网段 */
            form_get(c, ur[i], s, sizeof s);
            char *t = !strncmp(s, "https://", 8) ? fetch(s) : NULL;
            if (t) { snprintf(buf, REQ_MAX, "%s", t); free(t); }
            if (!buf[0] && i < 2) snprintf(buf, REQ_MAX, "%s", i == 0 ? DEF4 : DEF6);
        }
        n = i == 2 ? gather_dom(cand, n, buf, ndom) : gather(cand, n, buf, samples, nseg);
    }
    if (!n) { setphase("没有可用候选：请检查网段 / 域名列表"); return; }

    e_to = e_cert = e_conn = e_oth = 0;
    setphase("真实 TLS 测速中"); prog(n); run_pool(cand, n);
    int g = 0, hs = 0;
    for (int i = 0; i < n; i++) { if (cand[i].ok > 0) hs++; if (pass(&cand[i], maxloss, minms, maxms)) cand[g++] = cand[i]; }
    qsort(cand, (size_t)g, sizeof *cand, cmp);
    if (dl_on && g) {                                 /* 只对延迟最低的一批做下载测速（逐个进行，避免互相抢带宽） */
        int k = g < want * 2 ? g : want * 2; if (k > 60) k = 60;
        setphase("下载测速中"); prog(k);
        for (int i = 0; i < k; i++) { cand[i].mbps = speed_test(&cand[i]); pthread_mutex_lock(&mu); done++; pthread_mutex_unlock(&mu); }
        int q = 0; for (int i = 0; i < k; i++) if (cand[i].mbps >= dl_min) cand[q++] = cand[i];
        g = q; qsort(cand, (size_t)g, sizeof(Item), cmp_speed);
    }
    if (g > want) g = want;

    pthread_mutex_lock(&mu);
    free(res); res = malloc(sizeof(Item) * (size_t)(g ? g : 1));
    if (res) { memcpy(res, cand, sizeof(Item) * (size_t)g); nres = g; } else nres = 0;
    pthread_mutex_unlock(&mu);

    if (g) save_results();                            /* 供手动上传使用，重启后仍在 */
    if (!g) {
        char m[480];
        snprintf(m, sizeof m, "没有符合条件的结果：候选 %d 个，TLS 握手成功 %d 个；失败原因 超时 %d / 证书 %d / 连接 %d / 其他 %d。%s", n, hs, e_to, e_cert, e_conn, e_oth,
                 sus ? "⚠️ 检测到可能开启了代理/VPN，请关闭后重试（代理下的结果可能有误）" : hs ? "握手成功的 IP 被延迟 / 丢包 / 下载速度条件过滤，请放宽条件" : "请确认 SNI 已托管在 Cloudflare、系统有 CA 证书、网络为直连");
        setphase(m); return;
    }
    setphase("筛选完成");
    upload_all(c, cand, g, maxloss, minms, maxms);
    if (sus) addphase("｜⚠️ 筛选时疑似开启了代理 / VPN，结果可能有误");
}
static void *job(void *arg) {
    char *c = arg; Item *cand = calloc(MAXIP, sizeof *cand); char *buf = malloc(REQ_MAX);
    if (cand && buf) run_job(c, cand, buf); else setphase("内存不足");
    char msg[8192]; summary(msg, sizeof msg); notify(c, msg);   /* 每次筛选 + 上传结束后通知 */
    free(cand); free(buf); free(c);
    pthread_mutex_lock(&mu); running = 0; pthread_mutex_unlock(&mu);
    return NULL;
}

/* ---------- 启动 / 定时 / 开机自启 / 打开页面 ---------- */
static void mark_run(void) {
    last_run = time(NULL); FILE *f = fopen("data/last_run.txt", "w");
    if (f) { fprintf(f, "%ld\n", (long)last_run); fclose(f); }
}
static int start_job(const char *body) {              /* 0 已启动 / 1 正忙 / 2 失败 */
    pthread_mutex_lock(&mu); int busy = running; if (!busy) { running = 1; links[0] = 0; nres = 0; } pthread_mutex_unlock(&mu);
    if (busy) return 1;
    char *copy = strdup(body); pthread_t th;
    if (!copy || pthread_create(&th, NULL, job, copy)) { free(copy); pthread_mutex_lock(&mu); running = 0; pthread_mutex_unlock(&mu); return 2; }
    pthread_detach(th); mark_run(); return 0;
}
typedef struct { char *c; int kind; } Mj;
static void *manual_job(void *arg) {                 /* 手动上传：继续上次未完成的上传，或把最近一次结果上传一遍 */
    Mj *j = arg; Item *good = calloc(MAXIP, sizeof *good); int ng = good ? load_results(good, MAXIP) : 0, r = -1, minms, maxms; double maxloss;
    parse_params(j->c, &maxloss, &minms, &maxms);
    e_to = e_cert = e_conn = e_oth = 0;
    pthread_mutex_lock(&mu);
    if (nres == 0 && ng > 0 && !res) { int k = ng < 500 ? ng : 500; res = malloc(sizeof(Item) * (size_t)k); if (res) { memcpy(res, good, sizeof(Item) * (size_t)k); nres = k; } }
    pthread_mutex_unlock(&mu);
    setphase(j->kind == 1 ? "GitHub 手动上传中" : "SFTP 手动上传中");
    if (!good) setphase("内存不足");
    else {
        r = upload_target(j->c, j->kind, good, ng, maxloss, minms, maxms, 1);
        if (r == 0) setphase(j->kind == 1 ? "未填写完整的 GitHub 上传信息" : "未填写完整的 SFTP 上传信息");
        else if (r == 1) setphase(j->kind == 1 ? "GitHub 手动上传完成" : "SFTP 手动上传完成");
    }
    char msg[8192]; summary(msg, sizeof msg); notify(j->c, msg);
    free(good); free(j->c); free(j);
    pthread_mutex_lock(&mu); running = 0; pthread_mutex_unlock(&mu);
    return NULL;
}
static int start_manual(const char *body, int kind) {   /* 0 已启动 / 1 正忙 / 2 失败 */
    pthread_mutex_lock(&mu); int busy = running; if (!busy) running = 1; pthread_mutex_unlock(&mu);
    if (busy) return 1;
    Mj *j = malloc(sizeof *j); pthread_t th;
    if (j) { j->c = strdup(body); j->kind = kind; }
    if (!j || !j->c || pthread_create(&th, NULL, manual_job, j)) {
        if (j) { free(j->c); free(j); }
        pthread_mutex_lock(&mu); running = 0; pthread_mutex_unlock(&mu); return 2;
    }
    pthread_detach(th); return 0;
}
static void *scheduler(void *a) {                     /* 每 30 秒检查：固定间隔（小时）或每周某天某时 */
    (void)a;
    for (;;) {
        sleep(30);
        pthread_mutex_lock(&mu); char *c = cfg[0] ? strdup(cfg) : NULL; pthread_mutex_unlock(&mu);
        if (!c) continue;
        char mode[16], tms[16]; form_get(c, "sch_mode", mode, sizeof mode);
        time_t now = time(NULL); int due = 0;
        if (!strcmp(mode, "hours")) due = now >= last_run + (time_t)form_int(c, "sch_hours", 24, 1, 720) * 3600;
        else if (!strcmp(mode, "weekly")) {
            int hh = 2, mm = 0; form_get(c, "sch_time", tms, sizeof tms); sscanf(tms, "%d:%d", &hh, &mm);
            struct tm lt; localtime_r(&now, &lt);
            if (lt.tm_wday == form_int(c, "sch_wd", 1, 0, 6)) {
                lt.tm_hour = hh; lt.tm_min = mm; lt.tm_sec = 0; time_t t = mktime(&lt);
                due = now >= t && last_run < t;
            }
        }
        if (due) start_job(c);
        free(c);
    }
    return NULL;
}
static void save_cfg(const char *body) {
    mkdir("data", 0700); save_secrets(body);
    pthread_mutex_lock(&mu); strip_sec(body, cfg, sizeof cfg); pthread_mutex_unlock(&mu);
    FILE *f = fopen("data/config.txt", "w"); if (f) { fputs(cfg, f); fclose(f); }
}
/* Linux systemd 用户服务 / macOS LaunchAgent / Termux:Boot：均无需 root，下次开机或登录生效 */
static const char *autostart(void) {
#ifdef __ANDROID__
    if (!getenv("TERMUX_VERSION")) return "安卓 App 已内置前台服务和开机启动，请在系统设置里允许本应用「自启动」和「后台运行」";
#endif
    const char *home = getenv("HOME"); char path[700]; FILE *f;
    if (!home || !self[0]) return "无法确定程序路径";
    if (getenv("TERMUX_VERSION")) {
        sh("mkdir -p '%s/.termux/boot'", home); snprintf(path, sizeof path, "%s/.termux/boot/cfip.sh", home);
        if (!(f = fopen(path, "w"))) return "写入失败";
        fprintf(f, "#!/data/data/com.termux/files/usr/bin/sh\ntermux-wake-lock\ncd '%s' && exec '%s' --no-browser %d '%s'\n", wd, self, g_port, page);
        fclose(f); chmod(path, 0755);
        return "已写入 Termux:Boot 脚本（需安装 Termux:Boot 应用），下次开机生效";
    }
#ifdef __APPLE__
    sh("mkdir -p '%s/Library/LaunchAgents'", home); snprintf(path, sizeof path, "%s/Library/LaunchAgents/com.amos.cfip.plist", home);
    if (!(f = fopen(path, "w"))) return "写入失败";
    fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>com.amos.cfip</string>"
               "<key>ProgramArguments</key><array><string>%s</string><string>--no-browser</string><string>%d</string><string>%s</string></array>"
               "<key>EnvironmentVariables</key><dict><key>CFIP_HOME</key><string>%s</string></dict>"
               "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n", self, g_port, page, wd);
    fclose(f); return "已写入 LaunchAgent，下次登录生效";
#else
    sh("mkdir -p '%s/.config/systemd/user'", home); snprintf(path, sizeof path, "%s/.config/systemd/user/cfip.service", home);
    if (!(f = fopen(path, "w"))) return "写入失败";
    fprintf(f, "[Unit]\nDescription=CF IP optimizer\nAfter=network-online.target\n\n[Service]\nEnvironment=CFIP_HOME=%s\nWorkingDirectory=%s\n"
               "ExecStart=%s --no-browser %d %s\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n", wd, wd, self, g_port, page);
    fclose(f);
    if (sh("systemctl --user daemon-reload && systemctl --user enable cfip >/dev/null 2>&1 && loginctl enable-linger \"$USER\" >/dev/null 2>&1"))
        return "服务文件已写入，但 systemctl 设置失败，请手动执行：systemctl --user enable cfip";
    return "已设为开机自启（systemd 用户服务），下次开机生效";
#endif
}
static void open_ui(int port) {                       /* 程序启动后直接打开页面 */
    if (getenv("CFIP_NO_BROWSER")) return;
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%d/", port);
#if defined(__ANDROID__)
    if (getenv("TERMUX_VERSION")) sh("termux-open-url '%s' >/dev/null 2>&1 &", url);
#elif defined(__APPLE__)
    sh("open '%s' >/dev/null 2>&1 &", url);
#else
    const char *os = getenv("OS");
    if (os && !strcmp(os, "Windows_NT")) sh("cmd.exe //c start \"\" \"%s\" >/dev/null 2>&1", url);
    else if (getenv("DISPLAY") || getenv("WAYLAND_DISPLAY")) sh("xdg-open '%s' >/dev/null 2>&1 &", url);
#endif
}

/* ---------- HTTP 服务（每个连接一个线程） ---------- */
static void reply(int fd, int code, const char *type, const char *body, size_t n) {
    dprintf(fd, "HTTP/1.1 %d X\r\nContent-Type: %s; charset=utf-8\r\nContent-Length: %zu\r\n"
                "Cache-Control: no-store\r\n%sConnection: close\r\n\r\n", code, type, n, xhdr ? xhdr : "");
    xhdr = NULL;
    for (size_t o = 0; o < n;) { ssize_t w = write(fd, body + o, n - o); if (w <= 0) break; o += (size_t)w; }
}
#define RS(fd, code, type, s) reply(fd, code, type, s, strlen(s))

static void jesc(char *o, size_t n, const char *s) {
    size_t k = 0;
    for (; *s && k + 7 < n; s++) {
        if (*s == '"' || *s == '\\') { o[k++] = '\\'; o[k++] = *s; }
        else if (*s == '\n') { o[k++] = '\\'; o[k++] = 'n'; }
        else if ((unsigned char)*s >= 32) o[k++] = *s;
    }
    o[k] = 0;
}
static char *find_ci(char *h, const char *n) { size_t l = strlen(n); for (; *h; h++) if (!strncasecmp(h, n, l)) return h; return NULL; }

static void handle(int fd) {
    struct timeval tv = { 5, 0 }; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char *rq = malloc(REQ_MAX); if (!rq) return;
    size_t n = 0; char *hb = NULL; long need = -1; ssize_t k;
    while (n < REQ_MAX - 1 && (k = read(fd, rq + n, REQ_MAX - 1 - n)) > 0) {
        n += (size_t)k; rq[n] = 0;
        if (!hb && (hb = strstr(rq, "\r\n\r\n"))) {
            hb += 4; char *cl = find_ci(rq, "content-length:");
            need = (long)(hb - rq) + ((cl && cl < hb) ? atol(cl + 15) : 0);
        }
        if (hb && (long)n >= need) break;
    }
    if (hb && (long)n < need) { RS(fd, 413, "text/plain", "请求内容过大或不完整"); free(rq); return; }
    char m[8] = "", p[1024] = "";
    if (!hb || sscanf(rq, "%7s %1023s", m, p) != 2) { free(rq); return; }

    if (!strcmp(p, "/") || !strcmp(p, "/index.html")) {
        FILE *f = fopen(html_path, "rb");
        if (!f) RS(fd, 404, "text/plain", "找不到前端文件 web/index.html");
        else {
            fseek(f, 0, SEEK_END); long L = ftell(f); rewind(f);
            char *b = malloc((size_t)L + 1);
            if (b) { size_t r = fread(b, 1, (size_t)L, f); reply(fd, 200, "text/html", b, r); free(b); }
            fclose(f);
        }
    } else if (!strncmp(p, "/api/status", 11)) {
        char *o = malloc(80000), ph[3200], lk[4096], nt[500];
        if (o) {
            int pg = count_pending(1), ps = count_pending(2);
            pthread_mutex_lock(&mu); jesc(ph, sizeof ph, phase); jesc(lk, sizeof lk, links); jesc(nt, sizeof nt, notes);
            int len = snprintf(o, 80000, "{\"running\":%d,\"phase\":\"%s\",\"done\":%d,\"total\":%d,\"links\":\"%s\",\"note\":\"%s\",\"pend_gh\":%d,\"pend_sf\":%d,\"items\":[", running, ph, done, total, lk, nt, pg, ps);
            for (int i = 0; i < nres && len < 78000; i++) {
                char e[330]; fmt_entry(&res[i], "", e, sizeof e);
                len += snprintf(o + len, 80000 - (size_t)len, "%s{\"ip\":\"%s\",\"ms\":%.1f,\"loss\":%.2f,\"mbps\":%.2f}", i ? "," : "", e, res[i].ms, 1.0 - (double)res[i].ok / res[i].tries, res[i].mbps);
            }
            snprintf(o + len, 80000 - (size_t)len, "]}");
            pthread_mutex_unlock(&mu); RS(fd, 200, "application/json", o); free(o);
        }
    } else if (!strncmp(p, "/api/config", 11)) {
        size_t cap = REQ_MAX + 160; char *o = malloc(cap);
        if (o) {
            pthread_mutex_lock(&mu); size_t L = (size_t)snprintf(o, cap, "%s", cfg); pthread_mutex_unlock(&mu);
            for (int i = 0; SEC[i]; i++) { char v[8]; form_get(secrets, SEC[i], v, sizeof v); L += (size_t)snprintf(o + L, cap - L, "&has_%s=%d", SEC[i], v[0] != 0); }
            RS(fd, 200, "text/plain", o); free(o);
        }
    } else if (!strncmp(p, "/api/proxy", 10)) {
        char w[200], jw[420], o[560]; int s = proxy_check(w, sizeof w); jesc(jw, sizeof jw, w);
        snprintf(o, sizeof o, "{\"sus\":%d,\"why\":\"%s\"}", s, jw); RS(fd, 200, "application/json", o);
    } else if (!strncmp(p, "/api/ips", 8)) {
        char u[512]; const char *qs = strchr(p, '?'); form_get(qs ? qs + 1 : "", "url", u, sizeof u);
        char *t = !strncmp(u, "https://", 8) ? fetch(u) : NULL;
        if (t) { RS(fd, 200, "text/plain", t); free(t); }
        else RS(fd, 502, "text/plain", strncmp(u, "https://", 8) ? "地址必须以 https:// 开头" : ferr);
    } else if (!strncmp(p, "/api/export", 11)) {
        int csv = strstr(p, "fmt=csv") != NULL; char *o = malloc(80000);
        if (o) {
            pthread_mutex_lock(&mu); int len = csv ? snprintf(o, 80000, "rank,host,port,latency_ms,loss,speed_mbps\n") : 0; o[len] = 0;
            for (int i = 0; i < nres && len < 78000; i++) {
                char e[330]; fmt_entry(&res[i], "", e, sizeof e);
                len += csv ? snprintf(o + len, 80000 - (size_t)len, "%d,%s,%d,%.1f,%.2f,%.2f\n", i + 1, res[i].host, res[i].port, res[i].ms, 1.0 - (double)res[i].ok / res[i].tries, res[i].mbps)
                           : snprintf(o + len, 80000 - (size_t)len, "%s\n", e);
            }
            pthread_mutex_unlock(&mu);
            xhdr = csv ? "Content-Disposition: attachment; filename=cf-ips.csv\r\n" : "Content-Disposition: attachment; filename=cf-ips.txt\r\n";
            RS(fd, 200, "text/plain", o); free(o);
        }
    } else if (!strcmp(m, "POST") && !strcmp(p, "/api/start")) {
        save_cfg(hb); int r = start_job(hb);
        RS(fd, r == 1 ? 409 : r ? 500 : 200, "text/plain", r == 1 ? "busy" : r ? "failed" : "started");
    } else if (!strcmp(m, "POST") && !strcmp(p, "/api/save")) {
        char md[16]; save_cfg(hb); form_get(hb, "sch_mode", md, sizeof md);
        if (md[0] && strcmp(md, "off")) mark_run();                  /* 定时从保存时刻开始计时 */
        RS(fd, 200, "text/plain", "saved");
    } else if (!strcmp(m, "POST") && !strcmp(p, "/api/autostart")) {
        RS(fd, 200, "text/plain", autostart());
    } else if (!strcmp(m, "POST") && !strcmp(p, "/api/test")) {
        pthread_mutex_lock(&mu); char *cc = strdup(cfg); pthread_mutex_unlock(&mu);
        int r = cc ? notify(cc, "🔔 CF 优选：测试通知，通道已连通") : 0; free(cc);
        RS(fd, 200, "text/plain", r ? "测试通知已发送，请查看 Telegram / 邮箱" : "没有发送成功：请检查 Token、Chat ID 或 SMTP 设置");
    } else if (!strcmp(m, "POST") && !strncmp(p, "/api/upload", 11)) {                 /* 手动上传 */
        char t[8]; const char *qs = strchr(p, '?'); form_get(qs ? qs + 1 : "", "t", t, sizeof t);
        int kind = !strcmp(t, "gh") ? 1 : !strcmp(t, "sf") ? 2 : 0;
        if (!kind) RS(fd, 400, "text/plain", "bad target");
        else { save_cfg(hb); int r = start_manual(hb, kind); RS(fd, r == 1 ? 409 : r ? 500 : 200, "text/plain", r == 1 ? "busy" : r ? "failed" : "started"); }
    } else if (!strcmp(m, "POST") && !strncmp(p, "/api/view_save", 14)) {              /* 保存「查看」里的草稿 */
        char t[8], name[100], msg[240], jm[500], o[600]; int ok = 0, busy; form_get(hb, "t", t, sizeof t); form_get(hb, "name", name, sizeof name);
        char *text = malloc(strlen(hb) + 1);
        pthread_mutex_lock(&mu); busy = running; pthread_mutex_unlock(&mu);
        if (busy) snprintf(msg, sizeof msg, "任务运行中，请稍后再保存");
        else if (!text) snprintf(msg, sizeof msg, "内存不足");
        else { form_get(hb, "text", text, strlen(hb) + 1); ok = save_draft(t, name, text, msg, sizeof msg); }
        free(text); jesc(jm, sizeof jm, msg); snprintf(o, sizeof o, "{\"ok\":%d,\"msg\":\"%s\"}", ok, jm); RS(fd, 200, "application/json", o);
    } else if (!strcmp(m, "POST") && !strncmp(p, "/api/view", 9)) {                    /* 查看远端 / 待上传内容 */
        char t[8]; const char *qs = strchr(p, '?'); form_get(qs ? qs + 1 : "", "t", t, sizeof t);
        int kind = !strcmp(t, "gh") ? 1 : !strcmp(t, "sf") ? 2 : 0, busy;
        pthread_mutex_lock(&mu); busy = running; pthread_mutex_unlock(&mu);
        if (!kind) RS(fd, 400, "text/plain", "bad target");
        else if (busy) RS(fd, 200, "application/json", "{\"ok\":0,\"msg\":\"任务运行中，请等当前任务结束后再查看\"}");
        else { save_cfg(hb); char *j = view_target(hb, kind, form_int(hb, "reset", 0, 0, 1)); RS(fd, 200, "application/json", j); free(j); }
    } else RS(fd, 404, "text/plain", "not found");
    free(rq);
}
static void *conn(void *a) { int fd = (int)(intptr_t)a; handle(fd); close(fd); return NULL; }

int main(int argc, char **argv) {
    int ai = 1, as = 0;
    while (argc > ai && argv[ai][0] == '-') {
        if (!strcmp(argv[ai], "--autostart")) as = 1;
        else if (!strcmp(argv[ai], "--no-browser")) setenv("CFIP_NO_BROWSER", "1", 1);
        ai++;
    }
    int port = argc > ai ? atoi(argv[ai]) : DEFAULT_PORT; if (port < 1 || port > 65535) port = DEFAULT_PORT; g_port = port;
    ssize_t rl = readlink("/proc/self/exe", self, sizeof self - 1);
    if (rl > 0) self[rl] = 0; else if (!realpath(argv[0], self)) self[0] = 0;
    snprintf(exe_dir, sizeof exe_dir, "%s", self); char *sl = strrchr(exe_dir, '/'); if (sl) *sl = 0; else strcpy(exe_dir, ".");
    char want_html[4200];                                /* 前端文件默认在程序旁边的 web/index.html */
    if (argc > ai + 1) snprintf(want_html, sizeof want_html, "%s", argv[ai + 1]);
    else { snprintf(want_html, sizeof want_html, "%s/web/index.html", exe_dir); if (access(want_html, R_OK)) snprintf(want_html, sizeof want_html, "web/index.html"); }
    if (!realpath(want_html, page)) snprintf(page, sizeof page, "%s", want_html);
    snprintf(html_path, sizeof html_path, "%s", page);
    const char *hm = getenv("CFIP_HOME"); char hb[4200];  /* 数据目录：程序目录可写就用它，否则 ~/.cfip */
    if (!hm) {
        if (access(exe_dir, W_OK) == 0) hm = exe_dir;
        else { snprintf(hb, sizeof hb, "%s/.cfip", getenv("HOME") ? getenv("HOME") : "."); hm = hb; }
    }
    mkdir(hm, 0700);
    if (chdir(hm)) { perror("无法进入数据目录"); return 1; }
    if (!getcwd(wd, sizeof wd)) wd[0] = 0;
    if (as) { puts(autostart()); return 0; }

    signal(SIGPIPE, SIG_IGN); umask(077); setenv("GIT_TERMINAL_PROMPT", "0", 1);
    rs ^= (uint64_t)time(NULL) * 2654435761u;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) { fputs("libcurl 初始化失败\n", stderr); return 1; }
    mkdir("data", 0700); mkdir("data/stage", 0700); mkdir("data/manual", 0700);
    FILE *f = fopen("data/config.txt", "r"); if (f) { size_t r = fread(cfg, 1, sizeof cfg - 1, f); cfg[r] = 0; fclose(f); }
    if ((f = fopen("data/secrets.txt", "r"))) { size_t r = fread(secrets, 1, sizeof secrets - 1, f); secrets[r] = 0; fclose(f); }
    if ((f = fopen("data/last_run.txt", "r"))) { long t = 0; if (fscanf(f, "%ld", &t) == 1) last_run = (time_t)t; fclose(f); }
    if (!last_run) last_run = time(NULL);
    pthread_t sch; if (!pthread_create(&sch, NULL, scheduler, NULL)) pthread_detach(sch);

    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    const char *bind_ip = getenv("CFIP_BIND");
    if (inet_pton(AF_INET, bind_ip ? bind_ip : "127.0.0.1", &a.sin_addr) != 1) { fputs("CFIP_BIND 不是有效的 IPv4 地址\n", stderr); return 1; }
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 32)) {
        fprintf(stderr, "端口 %d 无法监听（可能已有一个实例在运行），已为你打开页面\n", port); open_ui(port); return 1;
    }
    printf("Amos · CF 优选已启动：http://127.0.0.1:%d/   数据目录：%s\n", port, wd);
    open_ui(port);
    for (;;) {
        int fd = accept(s, NULL, NULL); if (fd < 0) continue;
        pthread_t t; if (pthread_create(&t, NULL, conn, (void *)(intptr_t)fd)) close(fd); else pthread_detach(t);
    }
}
