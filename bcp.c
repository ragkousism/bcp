/*
** bcp.c -- broadcast copy -- Jordan Wilberding -- (C) 2012-2013

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

  See the folder LICENSE in the root folder of the project for more information.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <libgen.h>

#include "sha256.h"
#include "ed25519.h"

#define BROADCAST_PORT 4950   // default udp port
#define BCP_CODE 3141593      // have a unique code to verify broadcast
#define BCP_TCP_PORT 10789    // default tcp port
#define BACKLOG 10            // how many pending connections queue will hold
#define MAXBUFLEN 1024        // buffer size for udp packets
#define MAXNAMELEN 255        // max filename length
#define IO_BUFSIZE 16384      // file transfer buffer size

#define BCP_MAGIC "BCP2"
#define BCP_VERSION 1
#define BCP_NONCE_LEN 16
#define BCP_PUBKEY_LEN 32
#define BCP_SIG_LEN 64
#define BCP_HASH_LEN 32
#define BCP_HASH_SHA256 1

#define MAX_TRUST 16

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
  int allow_unauth;
  int gen_key;
  const char *key_path;
  const char *known_hosts_path;
  const char *trust_list[MAX_TRUST];
  int trust_count;
  const char *send_path;
} bcp_options;

static int file_exists(const char *filename)
{
  struct stat buffer;
  return (stat(filename, &buffer) == 0);
}

// get sockaddr, IPv4 or IPv6:
static void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static uint64_t bswap64(uint64_t v)
{
  return ((v & 0x00000000000000FFULL) << 56) |
         ((v & 0x000000000000FF00ULL) << 40) |
         ((v & 0x0000000000FF0000ULL) << 24) |
         ((v & 0x00000000FF000000ULL) << 8)  |
         ((v & 0x000000FF00000000ULL) >> 8)  |
         ((v & 0x0000FF0000000000ULL) >> 24) |
         ((v & 0x00FF000000000000ULL) >> 40) |
         ((v & 0xFF00000000000000ULL) >> 56);
}

static uint64_t htonll(uint64_t v)
{
  static const int num = 1;
  if (*(const char *)&num == 1) {
    return bswap64(v);
  }
  return v;
}

static uint64_t ntohll(uint64_t v)
{
  return htonll(v);
}

static int send_full(int fd, const void *buf, size_t len)
{
  const char *p = (const char *)buf;
  ssize_t sent;

  while (len > 0) {
    sent = send(fd, p, len, 0);
    if (sent < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (sent == 0) {
      return -1;
    }
    p += sent;
    len -= (size_t)sent;
  }

  return 0;
}

static int recv_full(int fd, void *buf, size_t len)
{
  char *p = (char *)buf;
  ssize_t recvd;

  while (len > 0) {
    recvd = recv(fd, p, len, 0);
    if (recvd < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (recvd == 0) {
      return -1;
    }
    p += recvd;
    len -= (size_t)recvd;
  }

  return 0;
}

static int hex_val(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

static int hex_decode(const char *hex, unsigned char *out, size_t outlen)
{
  size_t i = 0;
  int hi = -1;
  int v;

  while (*hex) {
    if (isspace((unsigned char)*hex)) {
      hex++;
      continue;
    }
    v = hex_val(*hex++);
    if (v < 0) {
      return -1;
    }
    if (hi < 0) {
      hi = v;
    }
    else {
      if (i >= outlen) {
        return -1;
      }
      out[i++] = (unsigned char)((hi << 4) | v);
      hi = -1;
    }
  }

  if (hi >= 0 || i != outlen) {
    return -1;
  }

  return 0;
}

static void hex_encode(const unsigned char *in, size_t len, char *out)
{
  static const char *hex = "0123456789abcdef";
  size_t i;

  for (i = 0; i < len; i++) {
    out[i * 2] = hex[(in[i] >> 4) & 0x0f];
    out[i * 2 + 1] = hex[in[i] & 0x0f];
  }
  out[len * 2] = '\0';
}

static int get_config_dir(char *buf, size_t len)
{
  const char *xdg = getenv("XDG_CONFIG_HOME");
  const char *home = getenv("HOME");

  if (xdg && *xdg) {
    if (snprintf(buf, len, "%s/bcp", xdg) >= (int)len) return -1;
    return 0;
  }
  if (home && *home) {
    if (snprintf(buf, len, "%s/.config/bcp", home) >= (int)len) return -1;
    return 0;
  }

  return -1;
}

static int ensure_dir(const char *path)
{
  char tmp[PATH_MAX];
  size_t len;
  char *p;

  len = strlen(path);
  if (len == 0 || len >= sizeof(tmp)) return -1;

  strncpy(tmp, path, sizeof(tmp));
  tmp[sizeof(tmp) - 1] = '\0';

  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      mkdir(tmp, 0700);
      *p = '/';
    }
  }

  if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
    return -1;
  }

  return 0;
}

static int default_key_path(char *buf, size_t len)
{
  char dir[PATH_MAX];
  if (get_config_dir(dir, sizeof(dir)) != 0) return -1;
  if (snprintf(buf, len, "%s/ed25519_key", dir) >= (int)len) return -1;
  return 0;
}

static int default_known_hosts_path(char *buf, size_t len)
{
  char dir[PATH_MAX];
  if (get_config_dir(dir, sizeof(dir)) != 0) return -1;
  if (snprintf(buf, len, "%s/known_hosts", dir) >= (int)len) return -1;
  return 0;
}

static int read_hex_file(const char *path, unsigned char *out, size_t outlen)
{
  FILE *fp;
  char line[4096];

  fp = fopen(path, "r");
  if (!fp) return -1;

  if (!fgets(line, sizeof(line), fp)) {
    fclose(fp);
    return -1;
  }
  fclose(fp);

  if (hex_decode(line, out, outlen) != 0) return -1;
  return 0;
}

static int write_hex_file(const char *path, const unsigned char *data, size_t len, mode_t mode)
{
  FILE *fp;
  char buf[2048];

  if (len * 2 + 2 > sizeof(buf)) return -1;

  hex_encode(data, len, buf);

  fp = fopen(path, "w");
  if (!fp) return -1;
  fprintf(fp, "%s\n", buf);
  fclose(fp);

  chmod(path, mode);
  return 0;
}

static int compute_fingerprint(const unsigned char *pubkey, char *out_hex, size_t out_len)
{
  SHA256_CTX ctx;
  unsigned char digest[BCP_HASH_LEN];

  if (out_len < (BCP_HASH_LEN * 2 + 1)) return -1;

  sha256_init(&ctx);
  sha256_update(&ctx, pubkey, BCP_PUBKEY_LEN);
  sha256_final(&ctx, digest);

  hex_encode(digest, sizeof(digest), out_hex);
  return 0;
}

static int known_hosts_contains(const char *path, const char *fingerprint)
{
  FILE *fp;
  char line[4096];
  char token[256];
  size_t i;

  fp = fopen(path, "r");
  if (!fp) return 0;

  while (fgets(line, sizeof(line), fp)) {
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') continue;
    token[0] = '\0';
    for (i = 0; i < sizeof(token) - 1 && line[i] && !isspace((unsigned char)line[i]); i++) {
      token[i] = (char)tolower((unsigned char)line[i]);
    }
    token[i] = '\0';
    if (token[0] != '\0' && strcmp(token, fingerprint) == 0) {
      fclose(fp);
      return 1;
    }
  }

  fclose(fp);
  return 0;
}

static int known_hosts_add(const char *path, const char *fingerprint, const char *label)
{
  FILE *fp;
  char dir[PATH_MAX];
  time_t now = time(NULL);

  if (get_config_dir(dir, sizeof(dir)) != 0) return -1;
  if (ensure_dir(dir) != 0) return -1;

  fp = fopen(path, "a");
  if (!fp) return -1;

  if (label && *label) {
    fprintf(fp, "%s %s %ld\n", fingerprint, label, (long)now);
  }
  else {
    fprintf(fp, "%s %ld\n", fingerprint, (long)now);
  }

  fclose(fp);
  return 0;
}

static int trust_list_contains(const bcp_options *opts, const char *fingerprint)
{
  int i;
  for (i = 0; i < opts->trust_count; i++) {
    if (strcasecmp(opts->trust_list[i], fingerprint) == 0) return 1;
  }
  return 0;
}

static int is_interactive(void)
{
  return isatty(STDIN_FILENO);
}

static int prompt_yes_no(const char *msg)
{
  char line[8];
  printf("%s", msg);
  if (!fgets(line, sizeof(line), stdin)) return 0;
  return (line[0] == 'y' || line[0] == 'Y');
}

static int ensure_sender_trust(const bcp_options *opts, const char *fingerprint, const char *label)
{
  char path[PATH_MAX];
  const char *kh_path = opts->known_hosts_path;
  int in_known = 0;

  if (!kh_path) {
    if (default_known_hosts_path(path, sizeof(path)) != 0) return -1;
    kh_path = path;
  }

  in_known = known_hosts_contains(kh_path, fingerprint);

  if (opts->trust_count > 0) {
    if (!trust_list_contains(opts, fingerprint)) {
      fprintf(stderr, "Untrusted sender key (fingerprint mismatch)\n");
      return -1;
    }
    if (!in_known) {
      if (known_hosts_add(kh_path, fingerprint, label) != 0) {
        fprintf(stderr, "Failed to store trusted key\n");
        return -1;
      }
    }
    return 0;
  }

  if (in_known) return 0;

  if (!is_interactive()) {
    fprintf(stderr, "Unknown sender key and no TTY; use --trust <fingerprint>\n");
    return -1;
  }

  printf("Sender key fingerprint: %s\n", fingerprint);
  if (!prompt_yes_no("Trust this key? y/N: ")) {
    return -1;
  }

  if (known_hosts_add(kh_path, fingerprint, label) != 0) {
    fprintf(stderr, "Failed to store trusted key\n");
    return -1;
  }

  return 0;
}

static int load_keypair(const bcp_options *opts, ed25519_secret_key sk, ed25519_public_key pk)
{
  char path[PATH_MAX];
  const char *key_path = opts->key_path;

  if (!key_path) {
    if (default_key_path(path, sizeof(path)) != 0) return -1;
    key_path = path;
  }

  if (read_hex_file(key_path, sk, sizeof(ed25519_secret_key)) != 0) {
    fprintf(stderr, "Failed to load private key: %s\n", key_path);
    return -1;
  }

  ed25519_publickey(sk, pk);
  return 0;
}

static int generate_keypair(void)
{
  char dir[PATH_MAX];
  char priv_path[PATH_MAX];
  char pub_path[PATH_MAX];
  ed25519_secret_key sk;
  ed25519_public_key pk;
  char fingerprint[BCP_HASH_LEN * 2 + 1];

  if (get_config_dir(dir, sizeof(dir)) != 0) {
    fprintf(stderr, "Failed to resolve config dir\n");
    return -1;
  }
  if (ensure_dir(dir) != 0) {
    fprintf(stderr, "Failed to create config dir: %s\n", dir);
    return -1;
  }
  if (snprintf(priv_path, sizeof(priv_path), "%s/ed25519_key", dir) >= (int)sizeof(priv_path)) return -1;
  if (snprintf(pub_path, sizeof(pub_path), "%s/ed25519_key.pub", dir) >= (int)sizeof(pub_path)) return -1;

  if (file_exists(priv_path) || file_exists(pub_path)) {
    fprintf(stderr, "Key files already exist in %s\n", dir);
    return -1;
  }

  ed25519_randombytes_unsafe(sk, sizeof(ed25519_secret_key));
  ed25519_publickey(sk, pk);

  if (write_hex_file(priv_path, sk, sizeof(ed25519_secret_key), 0600) != 0) return -1;
  if (write_hex_file(pub_path, pk, sizeof(ed25519_public_key), 0644) != 0) return -1;

  if (compute_fingerprint(pk, fingerprint, sizeof(fingerprint)) == 0) {
    printf("Generated keypair\n");
    printf("Private: %s\n", priv_path);
    printf("Public : %s\n", pub_path);
    printf("Fingerprint: %s\n", fingerprint);
  }

  return 0;
}

static size_t build_sign_payload(unsigned char *out, size_t out_len,
                                 const unsigned char *nonce,
                                 uint8_t hash_alg,
                                 uint64_t file_size,
                                 const char *filename,
                                 uint16_t filename_len,
                                 const unsigned char *file_hash)
{
  size_t needed = 4 + 1 + BCP_NONCE_LEN + 1 + 8 + 2 + filename_len + BCP_HASH_LEN;
  uint64_t size_net;
  uint16_t name_net;
  size_t off = 0;

  if (out_len < needed) return 0;

  memcpy(out + off, BCP_MAGIC, 4);
  off += 4;
  out[off++] = BCP_VERSION;
  memcpy(out + off, nonce, BCP_NONCE_LEN);
  off += BCP_NONCE_LEN;
  out[off++] = hash_alg;
  size_net = htonll(file_size);
  memcpy(out + off, &size_net, sizeof(size_net));
  off += sizeof(size_net);
  name_net = htons(filename_len);
  memcpy(out + off, &name_net, sizeof(name_net));
  off += sizeof(name_net);
  memcpy(out + off, filename, filename_len);
  off += filename_len;
  memcpy(out + off, file_hash, BCP_HASH_LEN);
  off += BCP_HASH_LEN;

  return off;
}

static void listener(char *ip, int *port)
{
  int sockfd;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  int numbytes;
  struct sockaddr_storage their_addr;
  char buf[MAXBUFLEN];
  socklen_t addr_len;
  uint32_t packet[2];
  char port_s[100];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  snprintf(port_s, sizeof(port_s), "%d", BROADCAST_PORT);

  if ((rv = getaddrinfo(NULL, port_s, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    exit(1);
  }

  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol)) == -1) {
      perror("listener: socket");
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("listener: bind");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "listener: failed to bind socket\n");
    exit(2);
  }

  freeaddrinfo(servinfo);

  addr_len = sizeof their_addr;

  int done = 0;

  while (!done) {
    if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
                             (struct sockaddr *)&their_addr, &addr_len)) == -1) {
      perror("recvfrom");
      exit(1);
    }
    else if (numbytes == (int)sizeof(packet)) {
             inet_ntop(their_addr.ss_family,
                       get_in_addr((struct sockaddr *)&their_addr),
                       ip, INET6_ADDRSTRLEN);

      memcpy(&packet, buf, sizeof(packet));

      if (ntohl(packet[0]) == BCP_CODE) {
        *port = ntohl(packet[1]);
        done = 1;
      }
    }
  }

  close(sockfd);
}

static void broadcaster(void)
{
  int sockfd;
  struct sockaddr_in their_addr;
  struct hostent *he;
  int numbytes;
  int broadcast = 1;

  if ((he=gethostbyname("255.255.255.255")) == NULL) {  // get the host info
    perror("gethostbyname");
    exit(1);
  }

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  // this call is what allows broadcast packets to be sent:
  if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                 sizeof broadcast) == -1) {
    perror("setsockopt (SO_BROADCAST)");
    exit(1);
  }

  their_addr.sin_family = AF_INET;     // host byte order
  their_addr.sin_port = htons(BROADCAST_PORT); // short, network byte order
  their_addr.sin_addr = *((struct in_addr *)he->h_addr);
  memset(their_addr.sin_zero, '\0', sizeof their_addr.sin_zero);

  uint32_t packet[2];
  packet[0] = htonl((uint32_t)BCP_CODE);
  packet[1] = htonl((uint32_t)BCP_TCP_PORT);

  if ((numbytes=sendto(sockfd, &packet, sizeof(packet), 0,
                       (struct sockaddr *)&their_addr, sizeof their_addr)) == -1) {
    perror("sendto");
    exit(1);
    }

  close(sockfd);
}

static void sigchld_handler(int s)
{
  (void)s;
  while(waitpid(-1, NULL, WNOHANG) > 0);
}

static int recv_legacy_file(int fd, uint32_t filename_size)
{
  char buf[IO_BUFSIZE];
  char filename[MAXNAMELEN + 1];
  int numbytes;
  FILE *ft;
  size_t total;
  char line[8];
  int overwrite = 0;

  if (filename_size == 0 || filename_size > MAXNAMELEN) {
    printf("Protocol error, exiting.\n");
    return -1;
  }

  if (recv_full(fd, filename, filename_size) != 0) {
    printf("Protocol error, exiting.\n");
    return -1;
  }
  filename[filename_size] = '\0';

  if (file_exists(filename)) {
    printf("%s already exists. Overwrite? y/N: ", filename);
    if (fgets(line, sizeof(line), stdin)) {
      if (line[0] == 'y' || line[0] == 'Y') overwrite = 1;
    }
    if (!overwrite) {
      return -1;
    }
  }

  ft = fopen(filename, "wb");
  if (ft == NULL) {
    perror("Cannot open file");
    return -1;
  }

  total = 0;
  while (1) {
    numbytes = recv(fd, buf, sizeof(buf), 0);
    if (numbytes < 0 && errno == EINTR) continue;
    if (numbytes <= 0) break;
    total += (size_t)numbytes;
    printf("\rReceive: %zu", total);
    fwrite(&buf, 1, (size_t)numbytes, ft);
  }

  printf("\nFile received: %s\n", filename);
  fclose(ft);
  return 0;
}

static int recv_secure_file(int fd, const bcp_options *opts, const char *peer_ip)
{
  unsigned char version;
  unsigned char nonce[BCP_NONCE_LEN];
  unsigned char challenge[4 + 1 + BCP_NONCE_LEN];
  unsigned char pubkey[BCP_PUBKEY_LEN];
  unsigned char hash_alg;
  uint16_t name_len_net;
  uint16_t name_len;
  uint64_t size_net;
  uint64_t file_size;
  char filename[MAXNAMELEN + 1];
  char fingerprint[BCP_HASH_LEN * 2 + 1];
  FILE *ft = NULL;
  unsigned char buf[IO_BUFSIZE];
  uint64_t remaining;
  size_t total = 0;
  int overwrite = 0;
  char line[8];
  SHA256_CTX ctx;
  unsigned char calc_hash[BCP_HASH_LEN];
  unsigned char recv_hash[BCP_HASH_LEN];
  ed25519_signature sig;
  unsigned char signbuf[512];
  size_t signlen;
  int rc = -1;

  if (recv_full(fd, &version, 1) != 0) {
    printf("Protocol error, exiting.\n");
    return -1;
  }
  if (version != BCP_VERSION) {
    printf("Unsupported protocol version.\n");
    return -1;
  }

  ed25519_randombytes_unsafe(nonce, sizeof(nonce));
  memcpy(challenge, BCP_MAGIC, 4);
  challenge[4] = BCP_VERSION;
  memcpy(challenge + 5, nonce, BCP_NONCE_LEN);
  if (send_full(fd, challenge, sizeof(challenge)) != 0) {
    printf("Failed to send challenge.\n");
    return -1;
  }

  if (recv_full(fd, pubkey, sizeof(pubkey)) != 0) return -1;
  if (recv_full(fd, &hash_alg, 1) != 0) return -1;
  if (recv_full(fd, &name_len_net, sizeof(name_len_net)) != 0) return -1;
  if (recv_full(fd, &size_net, sizeof(size_net)) != 0) return -1;

  name_len = ntohs(name_len_net);
  file_size = ntohll(size_net);

  if (hash_alg != BCP_HASH_SHA256) {
    printf("Unsupported hash algorithm.\n");
    return -1;
  }

  if (name_len == 0 || name_len > MAXNAMELEN) {
    printf("Protocol error, invalid filename.\n");
    return -1;
  }

  if (recv_full(fd, filename, name_len) != 0) return -1;
  filename[name_len] = '\0';

  if (compute_fingerprint(pubkey, fingerprint, sizeof(fingerprint)) != 0) return -1;
  if (ensure_sender_trust(opts, fingerprint, peer_ip) != 0) {
    return -1;
  }

  if (file_exists(filename)) {
    printf("%s already exists. Overwrite? y/N: ", filename);
    if (fgets(line, sizeof(line), stdin)) {
      if (line[0] == 'y' || line[0] == 'Y') overwrite = 1;
    }
    if (!overwrite) {
      return -1;
    }
  }

  ft = fopen(filename, "wb");
  if (ft == NULL) {
    perror("Cannot open file");
    return -1;
  }

  sha256_init(&ctx);
  remaining = file_size;
  while (remaining > 0) {
    size_t want = (remaining > sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
    ssize_t got = recv(fd, buf, want, 0);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) {
      printf("Connection error while receiving file.\n");
      goto cleanup;
    }
    fwrite(buf, 1, (size_t)got, ft);
    sha256_update(&ctx, buf, (size_t)got);
    remaining -= (uint64_t)got;
    total += (size_t)got;
    printf("\rReceive: %zu", total);
  }
  printf("\n");

  sha256_final(&ctx, calc_hash);

  if (recv_full(fd, recv_hash, sizeof(recv_hash)) != 0) {
    printf("Protocol error (hash).\n");
    goto cleanup;
  }
  if (recv_full(fd, sig, sizeof(sig)) != 0) {
    printf("Protocol error (signature).\n");
    goto cleanup;
  }

  if (memcmp(calc_hash, recv_hash, BCP_HASH_LEN) != 0) {
    printf("Hash mismatch; transfer corrupted.\n");
    goto cleanup;
  }

  signlen = build_sign_payload(signbuf, sizeof(signbuf), nonce, hash_alg, file_size,
                               filename, name_len, recv_hash);
  if (signlen == 0) {
    printf("Signature payload error.\n");
    goto cleanup;
  }

  if (ed25519_sign_open(signbuf, signlen, pubkey, sig) != 0) {
    printf("Signature verification failed.\n");
    goto cleanup;
  }

  printf("File received: %s\n", filename);
  rc = 0;

cleanup:
  if (ft) fclose(ft);
  if (rc != 0) {
    unlink(filename);
  }
  return rc;
}

static void server(int port, const bcp_options *opts)
{
  int sockfd, new_fd;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr;
  socklen_t sin_size;
  struct sigaction sa;
  int yes=1;
  char s[INET6_ADDRSTRLEN];
  int rv;
  char port_s[100];
  unsigned char first4[4];
  uint32_t filename_size_net;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  snprintf(port_s, sizeof(port_s), "%d", port);

  if ((rv = getaddrinfo(NULL, port_s, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    exit(1);
  }

  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol)) == -1) {
      perror("server: socket");
      continue;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                   sizeof(int)) == -1) {
      perror("setsockopt");
      exit(1);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("server: bind");
      continue;
    }

    break;
  }

  if (p == NULL)  {
    fprintf(stderr, "server: failed to bind\n");
    exit(2);
  }

  freeaddrinfo(servinfo);

  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }

  sin_size = sizeof their_addr;
  new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
  if (new_fd == -1) {
    perror("accept");
    close(sockfd);
    return;
  }

  inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
  printf("Incoming connection from: %s\n", s);

  if (recv_full(new_fd, first4, sizeof(first4)) != 0) {
    printf("Protocol error, exiting.\n");
    close(new_fd);
    close(sockfd);
    return;
  }

  if (memcmp(first4, BCP_MAGIC, 4) == 0) {
    if (recv_secure_file(new_fd, opts, s) != 0) {
      printf("Transfer failed.\n");
    }
  }
  else {
    if (!opts->allow_unauth) {
      printf("Legacy transfer rejected (use --allow-unauth to accept).\n");
    }
    else {
      memcpy(&filename_size_net, first4, sizeof(filename_size_net));
      if (recv_legacy_file(new_fd, ntohl(filename_size_net)) != 0) {
        printf("Transfer failed.\n");
      }
    }
  }

  close(new_fd);
  close(sockfd);
}

static int client_legacy(const char *ip, int port, const char *path)
{
  int sockfd;
  char buf[IO_BUFSIZE];
  struct addrinfo hints, *servinfo, *p;
  int rv;
  char s[INET6_ADDRSTRLEN];
  size_t size;
  FILE *ft;
  uint32_t filename_size;
  size_t total;
  char port_s[100];
  char *filename;
  char path_copy[PATH_MAX];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(port_s, sizeof(port_s), "%d", port);

  if ((rv = getaddrinfo(ip, port_s, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
  }

  // loop through all the results and connect to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("client: connect");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "client: failed to connect\n");
    freeaddrinfo(servinfo);
    return -1;
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);

  freeaddrinfo(servinfo);

  ft = fopen(path, "rb");
  if (ft == NULL) {
    perror("Cannot open file");
    close(sockfd);
    return -1;
  }

  strncpy(path_copy, path, sizeof(path_copy) - 1);
  path_copy[sizeof(path_copy) - 1] = '\0';
  filename = basename(path_copy);
  filename_size = (uint32_t)strlen(filename);
  filename_size = htonl(filename_size);

  memcpy(buf, &filename_size, sizeof(filename_size));
  memcpy(&buf[sizeof(filename_size)], filename, strlen(filename));

  if (send_full(sockfd, buf, sizeof(filename_size) + strlen(filename)) != 0) {
    perror("send");
  }

  total = 0;
  while (!feof(ft)) {
    size = fread(&buf, 1, sizeof(buf), ft);
    total += size;

    printf("\rSent: %zu", total);

    if (send_full(sockfd, buf, size) != 0)
      perror("send");
  }

  printf("\nFile sent.\n");

  close(sockfd);
  fclose(ft);
  return 0;
}

static int client_secure(const char *ip, int port, const char *path, const bcp_options *opts)
{
  int sockfd;
  unsigned char buf[IO_BUFSIZE];
  struct addrinfo hints, *servinfo, *p;
  int rv;
  char s[INET6_ADDRSTRLEN];
  FILE *ft;
  char port_s[100];
  char *filename;
  char path_copy[PATH_MAX];
  ed25519_secret_key sk;
  ed25519_public_key pk;
  uint16_t name_len;
  uint16_t name_len_net;
  uint64_t file_size;
  uint64_t size_net;
  struct stat st;
  unsigned char hello[5];
  unsigned char challenge[4 + 1 + BCP_NONCE_LEN];
  unsigned char nonce[BCP_NONCE_LEN];
  unsigned char hash_alg = BCP_HASH_SHA256;
  SHA256_CTX ctx;
  unsigned char file_hash[BCP_HASH_LEN];
  ed25519_signature sig;
  unsigned char signbuf[512];
  size_t signlen;
  uint64_t total = 0;

  if (load_keypair(opts, sk, pk) != 0) {
    fprintf(stderr, "Run: bcp --gen-key\n");
    return -1;
  }

  if (stat(path, &st) != 0) {
    perror("stat");
    return -1;
  }
  file_size = (uint64_t)st.st_size;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  snprintf(port_s, sizeof(port_s), "%d", port);

  if ((rv = getaddrinfo(ip, port_s, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
  }

  // loop through all the results and connect to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
                         p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("client: connect");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "client: failed to connect\n");
    freeaddrinfo(servinfo);
    return -1;
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);

  freeaddrinfo(servinfo);

  ft = fopen(path, "rb");
  if (ft == NULL) {
    perror("Cannot open file");
    close(sockfd);
    return -1;
  }

  strncpy(path_copy, path, sizeof(path_copy) - 1);
  path_copy[sizeof(path_copy) - 1] = '\0';
  filename = basename(path_copy);
  name_len = (uint16_t)strlen(filename);
  if (name_len == 0 || name_len > MAXNAMELEN) {
    fprintf(stderr, "Invalid filename length\n");
    fclose(ft);
    close(sockfd);
    return -1;
  }

  memcpy(hello, BCP_MAGIC, 4);
  hello[4] = BCP_VERSION;
  if (send_full(sockfd, hello, sizeof(hello)) != 0) {
    perror("send");
    fclose(ft);
    close(sockfd);
    return -1;
  }

  if (recv_full(sockfd, challenge, sizeof(challenge)) != 0) {
    fprintf(stderr, "Failed to read challenge\n");
    fclose(ft);
    close(sockfd);
    return -1;
  }

  if (memcmp(challenge, BCP_MAGIC, 4) != 0 || challenge[4] != BCP_VERSION) {
    fprintf(stderr, "Invalid challenge from receiver\n");
    fclose(ft);
    close(sockfd);
    return -1;
  }
  memcpy(nonce, challenge + 5, BCP_NONCE_LEN);

  name_len_net = htons(name_len);
  size_net = htonll(file_size);

  if (send_full(sockfd, pk, sizeof(pk)) != 0) goto send_err;
  if (send_full(sockfd, &hash_alg, 1) != 0) goto send_err;
  if (send_full(sockfd, &name_len_net, sizeof(name_len_net)) != 0) goto send_err;
  if (send_full(sockfd, &size_net, sizeof(size_net)) != 0) goto send_err;
  if (send_full(sockfd, filename, name_len) != 0) goto send_err;

  sha256_init(&ctx);
  while (!feof(ft)) {
    size_t n = fread(buf, 1, sizeof(buf), ft);
    if (n == 0) {
      if (ferror(ft)) {
        perror("fread");
        goto send_err;
      }
      break;
    }
    sha256_update(&ctx, buf, n);
    if (send_full(sockfd, buf, n) != 0) goto send_err;
    total += (uint64_t)n;
    printf("\rSent: %llu", (unsigned long long)total);
  }
  printf("\n");

  sha256_final(&ctx, file_hash);

  signlen = build_sign_payload(signbuf, sizeof(signbuf), nonce, hash_alg, file_size,
                               filename, name_len, file_hash);
  if (signlen == 0) goto send_err;

  ed25519_sign(signbuf, signlen, sk, pk, sig);

  if (send_full(sockfd, file_hash, sizeof(file_hash)) != 0) goto send_err;
  if (send_full(sockfd, sig, sizeof(sig)) != 0) goto send_err;

  printf("File sent.\n");

  fclose(ft);
  close(sockfd);
  return 0;

send_err:
  perror("send");
  fclose(ft);
  close(sockfd);
  return -1;
}

static void usage(void)
{
  printf("Usage:\n");
  printf("  bcp [options] [file]\n\n");
  printf("Options:\n");
  printf("  --gen-key                 Generate Ed25519 keypair\n");
  printf("  --allow-unauth             Allow legacy unauthenticated transfers\n");
  printf("  --trust <fingerprint>      Trust sender key (TOFU, non-interactive)\n");
  printf("  --known-hosts <path>       Override known_hosts path\n");
  printf("  --key <path>               Override private key path\n");
  printf("  --help                     Show this help\n");
}

int main(int argc, char *argv[])
{
  int port;
  char ip[INET6_ADDRSTRLEN];
  bcp_options opts;
  int i;

  memset(&opts, 0, sizeof(opts));

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--gen-key") == 0) {
      opts.gen_key = 1;
    }
    else if (strcmp(argv[i], "--allow-unauth") == 0) {
      opts.allow_unauth = 1;
    }
    else if (strcmp(argv[i], "--trust") == 0) {
      if (i + 1 >= argc || opts.trust_count >= MAX_TRUST) {
        fprintf(stderr, "--trust requires an argument\n");
        return 1;
      }
      opts.trust_list[opts.trust_count++] = argv[++i];
    }
    else if (strcmp(argv[i], "--known-hosts") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--known-hosts requires an argument\n");
        return 1;
      }
      opts.known_hosts_path = argv[++i];
    }
    else if (strcmp(argv[i], "--key") == 0 || strcmp(argv[i], "--priv") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "--key requires an argument\n");
        return 1;
      }
      opts.key_path = argv[++i];
    }
    else if (strcmp(argv[i], "--help") == 0) {
      usage();
      return 0;
    }
    else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      usage();
      return 1;
    }
    else {
      opts.send_path = argv[i];
    }
  }

  if (opts.gen_key) {
    return generate_keypair() == 0 ? 0 : 1;
  }

  if (opts.send_path) {
    printf("Listening for request..\n");
    listener(ip, &port);
    printf("Sending file to: %s:%d\n", ip, port);
    if (opts.allow_unauth) {
      return client_legacy(ip, port, opts.send_path) == 0 ? 0 : 1;
    }
    return client_secure(ip, port, opts.send_path, &opts) == 0 ? 0 : 1;
  }

  printf("Requesting file..\n");
  if (!fork()) { // this is the child process
    server(BCP_TCP_PORT, &opts);
  }
  else {
    sleep(1);
    broadcaster();
    int status;
    wait(&status);
  }

  return 0;
}
