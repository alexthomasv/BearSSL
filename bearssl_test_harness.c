#include "bearssl.h"
#include "ct-verif.h"

static const br_x509_trust_anchor TAs[2];
#define TAs_NUM   2

static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
    return 0;
	// for (;;) {
	// 	ssize_t rlen;

	// 	rlen = read(*(int *)ctx, buf, len);
	// 	if (rlen <= 0) {
	// 		if (rlen < 0 && errno == EINTR) {
	// 			continue;
	// 		}
	// 		return -1;
	// 	}
	// 	return (int)rlen;
	// }
}

static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
    return 0;
	// for (;;) {
	// 	ssize_t wlen;

	// 	wlen = write(*(int *)ctx, buf, len);
	// 	if (wlen <= 0) {
	// 		if (wlen < 0 && errno == EINTR) {
	// 			continue;
	// 		}
	// 		return -1;
	// 	}
	// 	return (int)wlen;
	// }
}

int br_sslio_write_all_wrapper(unsigned char *ioc, unsigned char *src, size_t len) {
    __SMACK_values(ioc, 40);
    __SMACK_values(src, 32);

    br_ssl_client_context sc;
	br_x509_minimal_context xc;
	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	int fd = 0;
	const char *host = "www.google.com";

    br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);

	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

	// br_ssl_client_reset(&sc, host, 0);
    
    br_sslio_init(ioc, &sc.eng, sock_read, &fd, sock_write, &fd);

    // __SMACK_value(len);
    return br_sslio_write_all(ioc, src, len);
}

void br_sslio_read_all_wrapper(void *ctx, void *dst, size_t len) {
    br_sslio_read_all(ctx, dst, len);
}


#ifdef TEST
#include <stdio.h>
#include <string.h>
#include <bearssl.h>

/* ---------- helper: stringify engine state bits ------------------- */
static const char *
state_str(int st)
{
    static char buf[64];
    buf[0] = 0;
    if (st & BR_SSL_CLOSED)  strcat(buf, "CLOSED ");
    if (st & BR_SSL_SENDREC) strcat(buf, "SENDREC ");
    if (st & BR_SSL_RECVREC) strcat(buf, "RECVREC ");
    if (st & BR_SSL_SENDAPP) strcat(buf, "SENDAPP ");
    if (st & BR_SSL_RECVAPP) strcat(buf, "RECVAPP ");
    return buf[0] ? buf : "NONE";
}

void dump_ssl_client(const br_ssl_client_context *sc)
{
    puts("br_ssl_client_context {");

    /* ----- fields that are publicly visible in the header ------- */
    printf("  min_clienthello_len = %u\n",  sc->min_clienthello_len);
    printf("  server_hashes       = 0x%08X\n", sc->hashes);
    printf("  server_curve        = %d\n",   sc->server_curve);
    printf("  client_auth_vtable  = %p\n",   (void *)sc->client_auth_vtable);
    printf("  auth_type           = %u\n",   sc->auth_type);
    printf("  hash_id             = 0x%02X\n", sc->hash_id);

    /* The union’s first member is a pointer, handy for quick checks */
    printf("  client_auth.vtable  = %p\n",   (void *)sc->client_auth.vtable);

    /* ----- a bit of engine info via public getters --------------- */
    {
        const br_ssl_engine_context *eng = &sc->eng;
        int st    = br_ssl_engine_current_state(eng);
        int vers  = br_ssl_engine_get_version(eng);
        br_ssl_session_parameters sp;
        br_ssl_engine_get_session_parameters(eng, &sp);

        puts("  engine {");
        printf("    state        = 0x%02X\n", st);
        printf("    TLS version  = 0x%04X\n", vers);
        printf("    cipher_suite = 0x%04X\n", sp.cipher_suite);
        puts("  }");
    }

    puts("}");
}


/* ---------- 3. br_x509_minimal_context ---------------------------- */
static void
dump_x509_minimal(const br_x509_minimal_context *xc)
{
    printf("\n[%s] br_x509_minimal_context @%p {\n",
           "dump_x509_minimal", (const void *)xc);

    /* server_name may be NULL */
    printf("  server_name        = %s\n",
           xc->server_name ? xc->server_name : "(none)");

    /* trust anchor count is public */
    printf("  trust_anchors_num  = %zu\n", xc->trust_anchors_num);

    /* validated key-usages (bitmask as per RFC 5280) */
    printf("  key_usages         = 0x%02X\n", xc->key_usages);


#ifdef BR_DUMP_INTERNALS
    /* ---------- INTERNAL (version-specific, may break) --------- */
    printf("  min_rsa_size       = %d bytes\n",
           xc->min_rsa_size + 128);   /* stored as diff from 128 */
    printf("  num_certs_seen     = %u (0 = EE)\n", xc->num_certs);
    printf("  do_mhash           = %u\n", xc->do_mhash);
    printf("  do_dn_hash         = %u\n", xc->do_dn_hash);
#endif

    printf("}\n");
}

static void
print_session_secret(const br_ssl_client_context *sc)
{
    const br_ssl_engine_context *eng = &sc->eng;
    br_ssl_session_parameters sp;

    /* Must be called *after* the handshake is complete */
    if (!br_ssl_engine_current_state(eng) & BR_SSL_SENDAPP) {
        printf("Handshake not finished yet.\n");
        return;
    }
    br_ssl_engine_get_session_parameters(eng, &sp);

    printf("Cipher-suite: 0x%04X\n", sp.cipher_suite);
    printf("Master secret (48 bytes):\n  ");
    for (size_t i = 0; i < sizeof sp.master_secret; i++) {
        printf("%02X", sp.master_secret[i]);
        if (i % 16 == 15) putchar('\n'), putchar(' ');
    }
    putchar('\n');
}

void main() {
	br_sslio_context ioc;
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	int fd = 0;
	const char *host = "www.google.com";

	br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
	br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);

    dump_ssl_client(&sc);
    dump_x509_minimal(&xc);
    print_session_secret(&sc);
	printf("sizeof(ioc): %zu\n", sizeof(ioc));
	br_sslio_write_all(&ioc, "Hello, World!", 13);
}
#endif