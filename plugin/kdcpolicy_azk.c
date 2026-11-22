/*
 * kdcpolicy_azk.c - MIT krb5 kdcpolicy module that applies a precomputed per-principal risk table.
 *
 * STATUS: WRITTEN AGAINST THE VERIFIED HEADER, NEVER COMPILED OR RUN. The development machine has no C
 * compiler and no Linux environment. Treat every line as untested until docs/05 "plugin bring-up" is done.
 *
 * Interface (verified against krb5 master src/include/krb5/kdcpolicy_plugin.h, major 1 / minor 1):
 *   kdcpolicy_azk_initvt(context, maj_ver, min_ver, vtable) ; vtable {name, init, fini, check_as, check_tgs}
 *   deny  = set *status to a string LITERAL and return a krb5 error code
 *   caps  = *lifetime_out / *renew_lifetime_out; krb5 only ever TIGHTENS (ts_min in src/kdc/policy.c);
 *           0 means "unconstrained", so this module never emits 0.
 *
 * Request-path cost: one time(), at most one stat() per second, one krb5_unparse_name, one hash and a
 * short linear probe in an mmap'd table. No network, no ML, no locks. Any problem => fail OPEN
 * (return 0, no restriction) so a broken scorer cannot become a denial-of-service lever.
 * The KDC being single-threaded (so the remap needs no lock) is ASSUMED, not verified.
 *
 * Config: krb5.conf   [plugins] kdcpolicy = { module = azk:/usr/lib/krb5/plugins/kdcpolicy/kdcpolicy_azk.so }
 *         (syntax from MIT's src/tests/t_kdcpolicy.py). Table path: env AZK_TABLE (default below).
 *
 * Table layout: see src/azk/risktable.py (little-endian, header 32 B, slot 88 B).
 *
 * Build (UNTESTED): gcc -shared -fPIC -O2 -Wall -o kdcpolicy_azk.so kdcpolicy_azk.c $(pkg-config --cflags krb5)
 */
#include <krb5/krb5.h>
#include "kdb.h"
#include <krb5/plugin.h>
#include <krb5/kdcpolicy_plugin.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define AZK_HDR_SIZE   32
#define AZK_SLOT_SIZE  88
#define AZK_NAME_LEN   64
#define AZK_VERSION    1
#define AZK_STALE_SECS 300
#define AZK_DENY_LEVEL 3
#define AZK_DEFAULT_PATH "/var/lib/azk/risk_table.bin"

struct azk_data {
    char *path;
    const uint8_t *map;
    size_t map_len;
    uint32_t nslots;
    uint64_t generated_at;
    ino_t ino;
    time_t mtime;
    off_t size;
    time_t last_stat;
};

static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; } /* host LE assumed (x86/ARM64) */
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static uint64_t fnv1a64(const char *s, size_t n)
{
    uint64_t h = 0xCBF29CE484222325ULL;
    size_t i;
    for (i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001B3ULL; }
    return h ? h : 1; /* matches risktable.fnv1a64: 0 is reserved for empty slots */
}

static void azk_unmap(struct azk_data *d)
{
    if (d->map) munmap((void *)d->map, d->map_len);
    d->map = NULL; d->map_len = 0; d->nslots = 0; d->generated_at = 0;
}

static void azk_reload(struct azk_data *d, time_t now)
{
    struct stat st;
    int fd;
    void *m;
    uint32_t nslots;

    d->last_stat = now;
    if (stat(d->path, &st) != 0) { azk_unmap(d); d->ino = 0; return; }
    if (d->map && st.st_ino == d->ino && st.st_mtime == d->mtime && st.st_size == d->size) return;
    if (st.st_size < AZK_HDR_SIZE + AZK_SLOT_SIZE) { azk_unmap(d); return; }
    fd = open(d->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { azk_unmap(d); return; }
    m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { azk_unmap(d); return; }
    {
        const uint8_t *b = m;
        nslots = rd32(b + 8);
        if (memcmp(b, "AZRT", 4) != 0 || rd32(b + 4) != AZK_VERSION || nslots == 0 ||
            (nslots & (nslots - 1)) != 0 ||
            (size_t)st.st_size != AZK_HDR_SIZE + (size_t)nslots * AZK_SLOT_SIZE) {
            munmap(m, (size_t)st.st_size);
            azk_unmap(d);
            return;
        }
        azk_unmap(d);
        d->map = b; d->map_len = (size_t)st.st_size; d->nslots = nslots;
        d->generated_at = rd64(b + 12);
        d->ino = st.st_ino; d->mtime = st.st_mtime; d->size = st.st_size;
    }
}

/* Returns 1 and fills outputs if a live, non-expired entry exists for `name`. */
static int azk_lookup(struct azk_data *d, const char *name, time_t now,
                      uint32_t *level, uint32_t *life, uint32_t *renew)
{
    size_t nl = strlen(name);
    uint64_t h;
    uint32_t i, probes;

    if (nl == 0 || nl >= AZK_NAME_LEN) return 0;
    if (now != d->last_stat) azk_reload(d, now);
    if (!d->map) return 0;
    if ((uint64_t)now > d->generated_at && (uint64_t)now - d->generated_at > AZK_STALE_SECS) return 0; /* stale => fail open */
    h = fnv1a64(name, nl);
    i = (uint32_t)(h & (d->nslots - 1));
    for (probes = 0; probes < d->nslots; probes++) {
        const uint8_t *s = d->map + AZK_HDR_SIZE + (size_t)i * AZK_SLOT_SIZE;
        uint64_t key = rd64(s);
        if (key == 0) return 0;
        if (key == h && memcmp(s + 8, name, nl) == 0 && s[8 + nl] == 0) {
            if ((uint64_t)rd32(s + 84) <= (uint64_t)now) return 0; /* expired => decays automatically */
            *level = rd32(s + 72); *life = rd32(s + 76); *renew = rd32(s + 80);
            return 1;
        }
        i = (i + 1) & (d->nslots - 1);
    }
    return 0;
}

static krb5_error_code azk_apply(krb5_context ctx, struct azk_data *d, krb5_const_principal who,
                                 const char *phase, const char **status,
                                 krb5_deltat *life_out, krb5_deltat *renew_out)
{
    char *name = NULL;
    uint32_t level = 0, life = 0, renew = 0;
    time_t now = time(NULL);
    int hit;

    if (who == NULL || krb5_unparse_name(ctx, who, &name) != 0) return 0;
    hit = azk_lookup(d, name, now, &level, &life, &renew);
    if (!hit) { krb5_free_unparsed_name(ctx, name); return 0; }

    if (level >= AZK_DENY_LEVEL) {
        syslog(LOG_NOTICE, "AZK_POLICY phase=%s client=%s level=%u lifetime=0 renew=0 deny=1 table_gen=%llu",
               phase, name, level, (unsigned long long)d->generated_at);
        krb5_free_unparsed_name(ctx, name);
        *status = "AZK_RISK_DENY"; /* must be a string literal */
        return KRB5KDC_ERR_POLICY;
    }
    if (life > 0 && life <= 0x7fffffffU) *life_out = (krb5_deltat)life;
    if (renew > 0 && renew <= 0x7fffffffU) *renew_out = (krb5_deltat)renew;
    syslog(LOG_NOTICE, "AZK_POLICY phase=%s client=%s level=%u lifetime=%u renew=%u deny=0 table_gen=%llu",
           phase, name, level, life, renew, (unsigned long long)d->generated_at);
    krb5_free_unparsed_name(ctx, name);
    return 0;
}

static krb5_error_code azk_init(krb5_context ctx, krb5_kdcpolicy_moddata *data_out)
{
    struct azk_data *d = calloc(1, sizeof(*d));
    const char *p = getenv("AZK_TABLE");
    (void)ctx;
    if (d == NULL) return ENOMEM;
    d->path = strdup(p && *p ? p : AZK_DEFAULT_PATH);
    if (d->path == NULL) { free(d); return ENOMEM; }
    openlog("azk-kdcpolicy", LOG_PID, LOG_AUTH);
    *data_out = (krb5_kdcpolicy_moddata)d; /* a missing table is fine: lookups fail open */
    return 0;
}

static krb5_error_code azk_fini(krb5_context ctx, krb5_kdcpolicy_moddata moddata)
{
    struct azk_data *d = (struct azk_data *)moddata;
    (void)ctx;
    if (d == NULL) return 0;
    azk_unmap(d);
    free(d->path);
    free(d);
    return 0;
}

static krb5_error_code azk_check_as(krb5_context ctx, krb5_kdcpolicy_moddata moddata,
                                    const krb5_kdc_req *request, const krb5_db_entry *client,
                                    const krb5_db_entry *server, const char *const *auth_indicators,
                                    const char **status, krb5_deltat *lifetime_out,
                                    krb5_deltat *renew_lifetime_out)
{
    (void)server; (void)auth_indicators;
    /* request->client is what the client asked for; with aliases / enterprise names (kinit -E)
     * it can differ from the canonical principal the KDC logs, which is the key the risk table
     * uses. Prefer the KDB entry's canonical principal; fall back to the requested name. */
    krb5_const_principal who = (client != NULL && client->princ != NULL) ? client->princ : request->client;
    return azk_apply(ctx, (struct azk_data *)moddata, who, "AS", status,
                     lifetime_out, renew_lifetime_out);
}

static krb5_error_code azk_check_tgs(krb5_context ctx, krb5_kdcpolicy_moddata moddata,
                                     const krb5_kdc_req *request, const krb5_db_entry *server,
                                     const krb5_ticket *ticket, const char *const *auth_indicators,
                                     const char **status, krb5_deltat *lifetime_out,
                                     krb5_deltat *renew_lifetime_out)
{
    (void)request; (void)server; (void)auth_indicators;
    /* UNVERIFIED: that ticket->enc_part2 is already decrypted/populated when this hook runs. */
    if (ticket == NULL || ticket->enc_part2 == NULL) return 0;
    return azk_apply(ctx, (struct azk_data *)moddata, ticket->enc_part2->client, "TGS", status,
                     lifetime_out, renew_lifetime_out);
}

krb5_error_code kdcpolicy_azk_initvt(krb5_context context, int maj_ver, int min_ver,
                                     krb5_plugin_vtable vtable)
{
    krb5_kdcpolicy_vtable vt;
    (void)context; (void)min_ver;
    if (maj_ver != 1) return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_kdcpolicy_vtable)vtable;
    vt->name = "azk";
    vt->init = azk_init;
    vt->fini = azk_fini;
    vt->check_as = azk_check_as;
    vt->check_tgs = azk_check_tgs;
    return 0;
}
