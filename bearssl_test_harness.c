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

        printf("sizeof(ioc): %zu\n", sizeof(ioc));
        br_sslio_write_all(&ioc, "Hello, World!", 13);
    }
#endif