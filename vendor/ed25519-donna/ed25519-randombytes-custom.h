/*
	a custom randombytes must implement:

	void ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len);

	ed25519_randombytes_unsafe is used by the batch verification function
	to create random scalars
*/

#include <fcntl.h>
#include <unistd.h>

static int
ed25519_read_urandom(void *p, size_t len) {
	int fd = open("/dev/urandom", O_RDONLY);
	unsigned char *out = (unsigned char *)p;
	ssize_t got;

	if (fd < 0) {
		return -1;
	}

	while (len > 0) {
		got = read(fd, out, len);
		if (got <= 0) {
			close(fd);
			return -1;
		}
		out += got;
		len -= (size_t)got;
	}

	close(fd);
	return 0;
}

void
ED25519_FN(ed25519_randombytes_unsafe) (void *p, size_t len) {
	if (ed25519_read_urandom(p, len) != 0) {
		/* last resort: zero fill */
		unsigned char *out = (unsigned char *)p;
		size_t i;
		for (i = 0; i < len; i++) {
			out[i] = 0;
		}
	}
}
