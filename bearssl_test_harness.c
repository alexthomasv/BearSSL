#include "bearssl.h"
#include "ct-verif.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "g_header.h"

/*
 * The hardcoded trust anchors. These are the two DN + public key that
 * correspond to the self-signed certificates cert-root-rsa.pem and
 * cert-root-ec.pem.
 *
 * C code for hardcoded trust anchors can be generated with the "brssl"
 * command-line tool (with the "ta" command).
 */

const char *host = "localhost";
static const unsigned char TA0_DN[] = {
	0x30, 0x1C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x43, 0x41, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x13, 0x04, 0x52, 0x6F, 0x6F, 0x74
};

static const unsigned char TA0_RSA_N[] = {
	0xB6, 0xD9, 0x34, 0xD4, 0x50, 0xFD, 0xB3, 0xAF, 0x7A, 0x73, 0xF1, 0xCE,
	0x38, 0xBF, 0x5D, 0x6F, 0x45, 0xE1, 0xFD, 0x4E, 0xB1, 0x98, 0xC6, 0x60,
	0x83, 0x26, 0xD2, 0x17, 0xD1, 0xC5, 0xB7, 0x9A, 0xA3, 0xC1, 0xDE, 0x63,
	0x39, 0x97, 0x9C, 0xF0, 0x5E, 0x5C, 0xC8, 0x1C, 0x17, 0xB9, 0x88, 0x19,
	0x6D, 0xF0, 0xB6, 0x2E, 0x30, 0x50, 0xA1, 0x54, 0x6E, 0x93, 0xC0, 0xDB,
	0xCF, 0x30, 0xCB, 0x9F, 0x1E, 0x27, 0x79, 0xF1, 0xC3, 0x99, 0x52, 0x35,
	0xAA, 0x3D, 0xB6, 0xDF, 0xB0, 0xAD, 0x7C, 0xCB, 0x49, 0xCD, 0xC0, 0xED,
	0xE7, 0x66, 0x10, 0x2A, 0xE9, 0xCE, 0x28, 0x1F, 0x21, 0x50, 0xFA, 0x77,
	0x4C, 0x2D, 0xDA, 0xEF, 0x3C, 0x58, 0xEB, 0x4E, 0xBF, 0xCE, 0xE9, 0xFB,
	0x1A, 0xDA, 0xA3, 0x83, 0xA3, 0xCD, 0xA3, 0xCA, 0x93, 0x80, 0xDC, 0xDA,
	0xF3, 0x17, 0xCC, 0x7A, 0xAB, 0x33, 0x80, 0x9C, 0xB2, 0xD4, 0x7F, 0x46,
	0x3F, 0xC5, 0x3C, 0xDC, 0x61, 0x94, 0xB7, 0x27, 0x29, 0x6E, 0x2A, 0xBC,
	0x5B, 0x09, 0x36, 0xD4, 0xC6, 0x3B, 0x0D, 0xEB, 0xBE, 0xCE, 0xDB, 0x1D,
	0x1C, 0xBC, 0x10, 0x6A, 0x71, 0x71, 0xB3, 0xF2, 0xCA, 0x28, 0x9A, 0x77,
	0xF2, 0x8A, 0xEC, 0x42, 0xEF, 0xB1, 0x4A, 0x8E, 0xE2, 0xF2, 0x1A, 0x32,
	0x2A, 0xCD, 0xC0, 0xA6, 0x46, 0x2C, 0x9A, 0xC2, 0x85, 0x37, 0x91, 0x7F,
	0x46, 0xA1, 0x93, 0x81, 0xA1, 0x74, 0x66, 0xDF, 0xBA, 0xB3, 0x39, 0x20,
	0x91, 0x93, 0xFA, 0x1D, 0xA1, 0xA8, 0x85, 0xE7, 0xE4, 0xF9, 0x07, 0xF6,
	0x10, 0xF6, 0xA8, 0x27, 0x01, 0xB6, 0x7F, 0x12, 0xC3, 0x40, 0xC3, 0xC9,
	0xE2, 0xB0, 0xAB, 0x49, 0x18, 0x3A, 0x64, 0xB6, 0x59, 0xB7, 0x95, 0xB5,
	0x96, 0x36, 0xDF, 0x22, 0x69, 0xAA, 0x72, 0x6A, 0x54, 0x4E, 0x27, 0x29,
	0xA3, 0x0E, 0x97, 0x15
};

static const unsigned char TA0_RSA_E[] = {
	0x01, 0x00, 0x01
};

static const unsigned char TA1_DN[] = {
	0x30, 0x1C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x43, 0x41, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x13, 0x04, 0x52, 0x6F, 0x6F, 0x74
};

static const unsigned char TA1_EC_Q[] = {
	0x04, 0x71, 0x74, 0xBA, 0xAB, 0xB9, 0x30, 0x2E, 0x81, 0xD5, 0xE5, 0x57,
	0xF9, 0xF3, 0x20, 0x68, 0x0C, 0x9C, 0xF9, 0x64, 0xDB, 0xB4, 0x20, 0x0D,
	0x6D, 0xEA, 0x40, 0xD0, 0x4A, 0x6E, 0x42, 0xFD, 0xB6, 0x9A, 0x68, 0x25,
	0x44, 0xF6, 0xDF, 0x7B, 0xC4, 0xFC, 0xDE, 0xDD, 0x7B, 0xBB, 0xC5, 0xDB,
	0x7C, 0x76, 0x3F, 0x41, 0x66, 0x40, 0x6E, 0xDB, 0xA7, 0x87, 0xC2, 0xE5,
	0xD8, 0xC5, 0xF3, 0x7F, 0x8D
};

static const br_x509_trust_anchor TAs[2] = {
	{
		{ (unsigned char *)TA0_DN, 30UL }, // dn
		BR_X509_TA_CA, // flags
		{
			BR_KEYTYPE_RSA,
			{ .rsa = {
				(unsigned char *)TA0_RSA_N, sizeof TA0_RSA_N,
				(unsigned char *)TA0_RSA_E, sizeof TA0_RSA_E,
			} }
		}
	},
	{
		{ (unsigned char *)TA1_DN, 30UL },
		BR_X509_TA_CA,
		{
			BR_KEYTYPE_EC,
			{ .ec = {
				BR_EC_secp256r1,
				(unsigned char *)TA1_EC_Q, sizeof TA1_EC_Q,
			} }
		}
	}
};
#define TAs_NUM   2

unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
int fd = 0;

void dump_buffer(unsigned char *buf, size_t len) {
	for (size_t i = 0; i < len; ++i)
        printf("%02X", buf[i]);   /* no spaces */
    putchar('\n');
}

int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t rlen;

		rlen = read(*(int *)ctx, buf, len); printf("$i201459 <- 0x%x $bb7577\n", rlen);
		if (rlen <= 0) {
			if (rlen < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		printf("msg: rlen: %zu\n", rlen);
		dump_buffer(buf, rlen);
		printf("msg end\n");
		return (int)rlen;
	}
}

int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t wlen;

		wlen = write(*(int *)ctx, buf, len); printf("msg: wlen: %zu\n", wlen); dump_buffer(buf, wlen); printf("msg end\n");
		if (wlen <= 0) {
			if (wlen < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		// dump_buffer(buf, wlen);
		return (int)wlen;
	}
}
// 0x6c6f63616c686f737400
int br_sslio_write_all_wrapper(
			unsigned char *ioc, 
			unsigned char *xc, 
			unsigned char *sc,
			unsigned char *src, 
			unsigned long long len) {
    public_in(__SMACK_value(ioc));
	public_in(__SMACK_value(xc));
	public_in(__SMACK_value(sc));
	public_in(__SMACK_value(src));
	public_in(__SMACK_value(len));

	public_in(__SMACK_values(ioc, 40));
    public_in(__SMACK_values(sc, 3720));
    public_in(__SMACK_values(xc, 3176));
    public_in(__SMACK_values(src, 30));
	
	// br_sslio_context ioc;
    // br_ssl_client_context sc;
	// br_x509_minimal_context xc;
	for (int i = 0; i < sizeof(TA0_DN); i++) printf(TA0_DN[i]);
	for (int i = 0; i < sizeof(TA0_RSA_N); i++) printf(TA0_RSA_N[i]);
	for (int i = 0; i < sizeof(TA0_RSA_E); i++) printf(TA0_RSA_E[i]);
	for (int i = 0; i < sizeof(TA1_DN); i++) printf(TA1_DN[i]);
	for (int i = 0; i < sizeof(TA1_EC_Q); i++) printf(TA1_EC_Q[i]);
	
    br_ssl_client_init_full(sc, xc, TAs, TAs_NUM);
	br_ssl_engine_set_buffer(&((br_ssl_client_context *)sc)->eng, iobuf, sizeof iobuf, 1);
	br_ssl_client_reset(sc, host, 0);
    br_sslio_init(ioc, &((br_ssl_client_context *)sc)->eng, sock_read, &fd, sock_write, &fd);
    return br_sslio_write_all(ioc, src, len);
}

// void br_sslio_read_all_wrapper(void *ctx, void *dst, size_t len) {
//     br_sslio_read_all(ctx, dst, len);
// }


#ifdef TEST
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

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

static int
host_connect(const char *host, const char *port)
{
	struct addrinfo hints, *si, *p;
	int fd;
	int err;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, port, &hints, &si);
	if (err != 0) {
		fprintf(stderr, "ERROR: getaddrinfo(): %s\n",
			gai_strerror(err));
		return -1;
	}
	fd = -1;
	for (p = si; p != NULL; p = p->ai_next) {
		struct sockaddr *sa;
		void *addr;
		char tmp[INET6_ADDRSTRLEN + 50];

		sa = (struct sockaddr *)p->ai_addr;
		if (sa->sa_family == AF_INET) {
			addr = &((struct sockaddr_in *)sa)->sin_addr;
		} else if (sa->sa_family == AF_INET6) {
			addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
		} else {
			addr = NULL;
		}
		if (addr != NULL) {
			inet_ntop(p->ai_family, addr, tmp, sizeof tmp);
		} else {
			sprintf(tmp, "<unknown family: %d>",
				(int)sa->sa_family);
		}
		fprintf(stderr, "connecting to: %s\n", tmp);
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) {
			perror("socket()");
			continue;
		}
		if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
			perror("connect()");
			close(fd);
			continue;
		}
		break;
	}
	if (p == NULL) {
		freeaddrinfo(si);
		fprintf(stderr, "ERROR: failed to connect\n");
		return -1;
	}
	freeaddrinfo(si);
	fprintf(stderr, "connected.\n");
	return fd;
}

void main() {
	br_sslio_context ioc;
	br_ssl_client_context sc;
	br_x509_minimal_context xc;
    const char *port = "5000";
	const char *path = "/";

    int fd = host_connect(host, port);
	if (fd < 0) {
		return -1;
	}

	br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
	br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
    br_ssl_client_reset(&sc, host, 0);
	br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);

    // dump_ssl_client(&sc);
    // dump_x509_minimal(&xc);
    // print_session_secret(&sc);
	printf("sizeof(ioc): %zu\n", sizeof(ioc));
	printf("sizeof(sc): %zu\n", sizeof(sc));
	printf("sizeof(xc): %zu\n", sizeof(xc));
	
	br_sslio_write_all(&ioc, "cache me if u can, houdini\r\n\r\n", 30);
	// br_sslio_write_all(&ioc, "\r\n\r\n", 4);
    // br_sslio_write_all(&ioc, "GET ", 4);
	// br_sslio_write_all(&ioc, path, g_strlen(path));
	// br_sslio_write_all(&ioc, " HTTP/1.0\r\nHost: ", 17);
	// br_sslio_write_all(&ioc, host, g_strlen(host));
	// br_sslio_write_all(&ioc, "\r\n\r\n", 4);
    br_sslio_flush(&ioc);

	for (;;) {
		int rlen;
		unsigned char tmp[512];

		rlen = br_sslio_read(&ioc, tmp, sizeof tmp);
		if (rlen < 0) {
			break;
		}
		fwrite(tmp, 1, rlen, stdout);
	}
	close(fd);
}
#endif