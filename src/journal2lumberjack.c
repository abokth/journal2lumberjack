//   Copyright 2015 Alexander Boström, Kungliga Tekniska högskolan
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

// This application reads logs from the systemd Journal in a
// structured format (key-value) and forwards them remotely through
// the lumberjack protocol.

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <error.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <systemd/sd-journal.h>
#include <zlib.h>
#include <string.h>
#include <wctype.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inotifytools/inotifytools.h>
#include <inotifytools/inotify.h>
#include <systemd/sd-daemon.h>

// NSS
#include <prerror.h>
#include <prinit.h>
#include <nss.h>
#include <pk11pub.h>
#include <secmod.h>
#include <ssl.h>
#include <sslproto.h>
NSPR_API(PRFileDesc*) PR_ImportTCPSocket(int);

#define min(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })
#define max(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })

static int verbose_flag;
static int help_flag;

void
usage() {
  fprintf(stderr, "Usage: journal2lumberjack [--stateless] --host <lumberjack host> --port <port> --certdb <lumberjack CA>\n");
}

void
__attribute__ ((noreturn)) errx(const char *description) {
  error(3, 0, "Error: %s", description);
  exit(3); // will never be reached
}

#define RUNTIME_CURSOR_FILE "/run/journal2lumberjack/acked-cursor"
#define PERSISTENT_CURSOR_FILE "/var/lib/journal2lumberjack/acked-cursor"

char *
load_cursor(const char *filename) {
  FILE *statefile = fopen(filename, "r");
  if (!statefile)
    return NULL;
  char *acked_cursor = NULL;
  char readbuf[1024];
  readbuf[1023] = '\0';
  if (fgets(readbuf, 1023, statefile) != NULL)
    acked_cursor = strdup(readbuf);
  fclose(statefile);
  return acked_cursor;
}

void
save_cursor(const char *filename, const char *acked_cursor) {
  FILE *statefile = fopen(filename, "w");
  if (statefile == NULL) error(3, errno, "State file update failed.");
  fprintf(statefile, acked_cursor);
  fclose(statefile);
}

#define RUNTIME_JOURNAL_DIR "/run/log/journal"
#define PERSISTENT_JOURNAL_DIR "/var/log/journal"

int
watch_journal_paths() {
  int persistent = 0;
  int found_journal = 0;

  struct stat s;
  int res;

  res = stat(RUNTIME_JOURNAL_DIR, &s);
  if (res == 0) {
    found_journal = 1;
    res = inotifytools_watch_recursively(RUNTIME_JOURNAL_DIR, IN_MODIFY | IN_CREATE);
    if (res == 0) errx("Inotify failure watching runtime journal.");
  }
    
  res = stat(PERSISTENT_JOURNAL_DIR, &s);
  if (res == 0) {
    found_journal = 1;
    res = inotifytools_watch_recursively(PERSISTENT_JOURNAL_DIR, IN_MODIFY | IN_CREATE);
    if (res == 0) errx("Inotify failure watching persistent journal.");
    persistent = 1;
  }

  if (!found_journal)
     errx("No journal found.");

  return persistent;
}

#define HAPPY_STATE_NONE 0
#define HAPPY_STATE_CONNECTING 1
#define HAPPY_STATE_CONNECTED 2
#define HAPPY_STATE_RETURNED 3
#define HAPPY_STATE_FAILED -1

struct happy_socket {
  struct addrinfo *addr;
  int fd;
  int state;
};

struct happy_eyeballs {
  struct addrinfo *server_addresses;
  int num_addr;
  struct happy_socket *sockets;
};

void
happy_eyeballs_lookup(struct happy_eyeballs **state_p, const char *host, const char *port) {
  struct happy_eyeballs *state = calloc(1, sizeof(struct happy_eyeballs));
  if (state == NULL) errx("Allocation failure.");

  // Happy eyeballs connect.
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;
  int res = getaddrinfo(host, port, &hints, &(state->server_addresses));
  if (res) error(3, 0, "Host name lookup failure.");

  // count results
  int results = 0;
  for (struct addrinfo *address = state->server_addresses; address != NULL; address = address->ai_next) {
    results++;
  }
  state->num_addr = results;

  struct addrinfo **addresses = calloc(state->num_addr, sizeof(struct addrinfo *));
  if (addresses == NULL) errx("Allocation failure.");

  int *ai_families = calloc(state->num_addr, sizeof(int));
  int addri = 0, num_fam = 0;
  for (struct addrinfo *address = state->server_addresses; address != NULL; address = address->ai_next) {
    addresses[addri++] = address;

    // Collect the set of ai_family
    for (int fami=0; fami<state->num_addr; fami++) {
      if (ai_families[fami] == address->ai_family) {
	break;
      } else if (ai_families[fami] == 0) {
	ai_families[fami] = address->ai_family;
	num_fam = fami+1;
	break;
      }
    }
  }

  state->sockets = (struct happy_socket *)calloc(state->num_addr, sizeof(struct happy_socket));
  if (state->sockets == NULL) errx("Allocation failure.");

  int order = 0, found = 1;
  while (found) {
    found = 0;
    for (int fami=0; fami<num_fam; fami++) {
      for (int i=0; i<state->num_addr; i++) {
	if (addresses[i] != NULL && addresses[i]->ai_family == ai_families[fami]) {
	  state->sockets[order++].addr = addresses[i];
	  addresses[i] = NULL;
	  found = 1;
	  break;
	}
      }
    }
  }

  if (state->num_addr != order) abort();

  free(ai_families);

  *state_p = state;
}

int
happy_eyeballs_connect(struct happy_eyeballs *state) {
  for (int i=0; i<state->num_addr; i++) {
    if (state->sockets[i].state == HAPPY_STATE_NONE) {
      // Try this one.
      struct addrinfo *address = state->sockets[i].addr;
      int new_socket = socket(address->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
      if (new_socket > 0) {
	state->sockets[i].fd = new_socket;

	int res;
	do {
	  res = connect(new_socket, address->ai_addr, address->ai_addrlen);
	} while (res == -1 && (errno == EAGAIN || errno == EINTR));

	if (res == -1 && errno == EINPROGRESS) {
	  state->sockets[i].state = HAPPY_STATE_CONNECTING;
	  break;
	} else if (res == 0) {
	  state->sockets[i].state = HAPPY_STATE_CONNECTED;
	  break;
	} else {
	  state->sockets[i].state = HAPPY_STATE_FAILED;
	}
      } else {
	state->sockets[i].state = HAPPY_STATE_FAILED;
      }
    }
  }

  fd_set waiting_fds;
  FD_ZERO(&waiting_fds);

  struct timeval wait;
  wait.tv_sec = 0;
  wait.tv_usec = 300000;

  int nfds = 0;
  for (int i=0; i<state->num_addr; i++) {
    if (state->sockets[i].state == HAPPY_STATE_CONNECTING) {
      FD_SET(state->sockets[i].fd, &waiting_fds);
      nfds = max(state->sockets[i].fd + 1, nfds);
    }
  }
  if (nfds) {
    int ret = select(nfds, NULL, &waiting_fds, NULL, &wait);
    if (ret == -1 && ret != EINTR) error(3, errno, "Error while waiting for connection.");

    for (int i=0; i<state->num_addr; i++) {
      if (FD_ISSET(state->sockets[i].fd, &waiting_fds)) {
	int val;
	socklen_t size = sizeof(val);
	if (getsockopt(state->sockets[i].fd, SOL_SOCKET, SO_ERROR, &val, &size) == 0 && val != SO_ERROR) {
	  state->sockets[i].state = HAPPY_STATE_CONNECTED;
	} else {
	  state->sockets[i].state = HAPPY_STATE_FAILED;
	}
      }
    }
  }

  int not_failed = 0;
  for (int i=0; i<state->num_addr; i++) {
    // Do we have a connected socket now?
    if (state->sockets[i].state == HAPPY_STATE_CONNECTED) {
      state->sockets[i].state = HAPPY_STATE_RETURNED;
      return state->sockets[i].fd;
    }

    // If not, do we have something that might connect in the future?
    if (state->sockets[i].state != HAPPY_STATE_RETURNED && state->sockets[i].state != HAPPY_STATE_FAILED) {
      not_failed = 1;
    }
  }

  if (not_failed)
    return 0;

  // the end
  return -1;
}

void
happy_eyeballs_close(struct happy_eyeballs *state) {
  for (int i=0; i<state->num_addr; i++) {
    if (state->sockets[i].state != HAPPY_STATE_NONE && state->sockets[i].state != HAPPY_STATE_RETURNED) {
      close(state->sockets[i].fd);
    }
  }
  free(state->sockets);
  freeaddrinfo(state->server_addresses);
  free(state);
}

// Initialize NSS library.
//  https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/sect-Defensive_Coding-TLS-Client-NSS.html
void
nspr_tls_init(const char *certdb) {

  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
  NSSInitContext *const ctx = NSS_InitContext(certdb, "", "", "", NULL, NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);

  if (ctx == NULL) {
    const PRErrorCode err = PR_GetError();
    error(3, 0, "TLS error: NSPR error code %d: %s", err, PR_ErrorToName(err));
  }

  // Ciphers to enable.
  static const PRUint16 good_ciphers[] = {
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
    SSL_NULL_WITH_NULL_NULL // sentinel
  };

  // Check if the current policy allows any strong ciphers.  If it
  // doesn't, set the cipher suite policy.  This is not thread-safe
  // and has global impact.  Consequently, we only do it if absolutely
  // necessary.
  int found_good_cipher = 0;
  for (const PRUint16 *p = good_ciphers; *p != SSL_NULL_WITH_NULL_NULL; ++p) {
    PRInt32 policy;
    if (SSL_CipherPolicyGet(*p, &policy) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      error(3, 0, "TLS error: NSPR policy for cipher %u: error %d: %s", (unsigned)*p, err, PR_ErrorToName(err));
    }
    if (policy == SSL_ALLOWED) {
      //fprintf(stderr, "info: found cipher %x\n", (unsigned)*p);
      found_good_cipher = 1;
      break;
    }
  }
  if (!found_good_cipher) {
    if (NSS_SetDomesticPolicy() != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      error(3, 0, "TLS/NSPR error: NSS_SetDomesticPolicy: error %d: %s", err, PR_ErrorToName(err));
    }
  }

  // Initialize the trusted certificate store.
  char module_name[] = "library=libnssckbi.so name=\"Root Certs\"";
  SECMODModule *module = SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);
  if (module == NULL || !module->loaded) {
    const PRErrorCode err = PR_GetError();
    error(3, 0, "TLS/NSPR error: NSPR error code %d: %s", err, PR_ErrorToName(err));
  }
}

PRFileDesc*
nspr_tls_handshake(const int sockfd, const char *host, char **error_p) {
  PRFileDesc* nspr = PR_ImportTCPSocket(sockfd);

  {
    PRFileDesc *model = PR_NewTCPSocket();
    PRFileDesc *newfd = SSL_ImportFD(NULL, model);
    if (newfd == NULL) {
      const PRErrorCode err = PR_GetError();
      if (*error_p) free(*error_p);
      if (asprintf(error_p, "error: NSPR error code %d: %s\n", err, PR_ErrorToName(err)) == -1) errx("Allocation failure.");
      return NULL;
    }
    model = newfd;
    newfd = NULL;
    if (SSL_OptionSet(model, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      if (*error_p) free(*error_p);
      if (asprintf(error_p, "error: set SSL_ENABLE_SSL2 to false error %d: %s\n", err, PR_ErrorToName(err)) == -1) errx("Allocation failure.");
      return NULL;
    }
    if (SSL_OptionSet(model, SSL_V2_COMPATIBLE_HELLO, PR_FALSE) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      if (*error_p) free(*error_p);
      if (asprintf(error_p, "error: set SSL_V2_COMPATIBLE_HELLO to false error %d: %s\n", err, PR_ErrorToName(err)) == -1) errx("Allocation failure.");
      return NULL;
    }
    if (SSL_OptionSet(model, SSL_ENABLE_DEFLATE, PR_FALSE) != SECSuccess) {
      const PRErrorCode err = PR_GetError();
      if (*error_p) free(*error_p);
      if (asprintf(error_p, "error: set SSL_ENABLE_DEFLATE to false error %d: %s\n", err, PR_ErrorToName(err)) == -1) errx("Allocation failure.");
      return NULL;
    }

    newfd = SSL_ImportFD(model, nspr);
    if (newfd == NULL) {
      const PRErrorCode err = PR_GetError();
      if (*error_p) free(*error_p);
      if (asprintf(error_p, "error: SSL_ImportFD error %d: %s\n", err, PR_ErrorToName(err)) == -1) errx("Allocation failure.");
      return NULL;
    }
    nspr = newfd;
    PR_Close(model);
  }

  if (SSL_ResetHandshake(nspr, PR_FALSE) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    if (*error_p) free(*error_p);
    if (asprintf(error_p, "error: SSL_ResetHandshake error %d: %s\n", err, PR_ErrorToName(err)) == -1) errx("Allocation failure.");
    return NULL;
  }
  if (SSL_SetURL(nspr, host) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    if (*error_p) free(*error_p);
    if (asprintf(error_p, "error: SSL_SetURL error %d: %s\n", err, PR_ErrorToName(err)) == -1) errx("Allocation failure.");
    return NULL;
  }
  if (SSL_ForceHandshake(nspr) != SECSuccess) {
    const PRErrorCode err = PR_GetError();
    if (*error_p) free(*error_p);
    if (asprintf(error_p, "error: SSL_ForceHandshake error %d: %s\n", err, PR_ErrorToName(err)) == -1) errx("Allocation failure.");
    return NULL;
  }

  return nspr;
}

PRFileDesc*
nspr_tls_connect(const char *host, const char *port) {
  struct happy_eyeballs *state = NULL;
  happy_eyeballs_lookup(&state, host, port);

  PRFileDesc* nsprconn = NULL;
  char *last_tls_error = NULL;
  do {
    int sockfd = happy_eyeballs_connect(state);
    if (sockfd == 0)
      continue;
    if (sockfd < 0) {
      if (last_tls_error != NULL)
	errx(last_tls_error);
      errx("No TCP connection could be established.");
    }
    nsprconn = nspr_tls_handshake(sockfd, host, &last_tls_error);
  } while (nsprconn == NULL);

  // We have a TLS connection now, disconnect all other connections.
  happy_eyeballs_close(state);
  return nsprconn;
}

void
nspr_tls_close(PRFileDesc* nsprconn) {
  if (PR_Shutdown(nsprconn, PR_SHUTDOWN_BOTH) != PR_SUCCESS) {
    const PRErrorCode err = PR_GetError();
    error(3, 0, "TLS/NSPR error: PR_Shutdown error %d: %s", err, PR_ErrorToName(err));
  }
  PR_Close(nsprconn);
}

#define STREAM_BUFFER_SIZE 1048576
#define SMALL_BUFFER_SIZE 128

struct iobuf {
  PRFileDesc* nsprconn;
  uint8_t *inbuf;
  uint8_t *outbuf;
  size_t inbuf_start; // first used byte
  size_t inbuf_consumed, outbuf_consumed; // first free byte
  size_t inbuf_size, outbuf_size;
  size_t outbuf_data_field_count_pos, outbuf_string_length_pos;
  int outbuf_data_queue;
};

struct iobuf *
new_iobuf(PRFileDesc* nsprconn) {
  struct iobuf *iobuf_p = calloc(1, sizeof(struct iobuf));
  iobuf_p->inbuf = calloc(STREAM_BUFFER_SIZE, sizeof(uint8_t));
  iobuf_p->outbuf = calloc(STREAM_BUFFER_SIZE, sizeof(uint8_t));
  iobuf_p->inbuf_size = STREAM_BUFFER_SIZE;
  iobuf_p->outbuf_size = STREAM_BUFFER_SIZE;
  iobuf_p->nsprconn = nsprconn;
  return iobuf_p;
}

struct iobuf *
iobuf_connect_tls(const char *host, const char *port) {
  PRFileDesc* nsprconn = nspr_tls_connect(host, port);
  return new_iobuf(nsprconn);
}

void
iobuf_close(struct iobuf *iobuf_p) {
  if (iobuf_p->nsprconn != NULL)
    nspr_tls_close(iobuf_p->nsprconn);
  free(iobuf_p->inbuf);
  free(iobuf_p->outbuf);
  free(iobuf_p);
}

int
poll_iobuf(struct iobuf *iobuf_p, size_t bytes) {
  if ( (iobuf_p->inbuf_consumed - iobuf_p->inbuf_start) < bytes ) {
    size_t free_buffer_space = min(iobuf_p->inbuf_size - iobuf_p->inbuf_consumed, (size_t)PR_INT32_MAX);
    PRInt32 count = PR_Read(iobuf_p->nsprconn, (void *)(&iobuf_p->inbuf[iobuf_p->inbuf_consumed]), (PRInt32)free_buffer_space);
    if (count <= 0) {
      const PRErrorCode err = PR_GetError();
      error(3, 0, "TLS read error: NSPR error code %d: %s", err, PR_ErrorToName(err));
    }
    iobuf_p->inbuf_consumed += count;
  }
  return (iobuf_p->inbuf_consumed - iobuf_p->inbuf_start) >= bytes;
}

void
read_buf_from_iobuf(struct iobuf *iobuf_p, const uint8_t *buf, size_t size) {
  size_t has_read = 0, to_read = size;

  size_t buffered_read = min(iobuf_p->inbuf_consumed - iobuf_p->inbuf_start, to_read);
  if (buffered_read > 0) {
    memcpy((void *)(&buf[has_read]), (void *)(&iobuf_p->inbuf[iobuf_p->inbuf_start]), buffered_read);
    iobuf_p->inbuf_start += buffered_read;

    if (iobuf_p->inbuf_start != 0 && iobuf_p->inbuf_start == iobuf_p->inbuf_consumed) {
      // We've read everything, reset buffer.
      iobuf_p->inbuf_start = 0;
      iobuf_p->inbuf_consumed = 0;
    }

    has_read = buffered_read;
  }

  while (has_read < to_read) {
    size_t left_to_read =  min(to_read - has_read, (size_t)PR_INT32_MAX);
    PRInt32 count = PR_Read(iobuf_p->nsprconn, (void *)(&buf[has_read]), (PRInt32)left_to_read);
    if (count <= 0) {
      const PRErrorCode err = PR_GetError();
      error(3, 0, "TLS read error: NSPR error code %d: %s", err, PR_ErrorToName(err));
    }
    has_read += count;
  }
}

void
lumberjack_package_frames(struct iobuf *iobuf_p) {
  int err;

  uLong min_alloc = compressBound(iobuf_p->outbuf_consumed) + 12;
  size_t to_alloc = iobuf_p->outbuf_size;
  while (to_alloc < min_alloc)
    to_alloc *= 2;

  uint8_t *compressbuf = calloc(to_alloc, sizeof(uint8_t));
  if (compressbuf == NULL) errx("Allocation failure.");
  uLong compressed_size = to_alloc - 12;

  // Set window size to the number of queued data frames.
  compressbuf[0] = '1';
  compressbuf[1] = 'W';
  uint32_t *window_size_p = (uint32_t *)(&(compressbuf[2]));
  *window_size_p = htonl(iobuf_p->outbuf_data_queue);

  err = compress(&compressbuf[12], &compressed_size, (const Bytef*)(iobuf_p->outbuf), (uLong)(iobuf_p->outbuf_consumed));
  if (err != Z_OK) errx("zlib compression error");

  // Start compressed frame.
  compressbuf[6] = '1';
  compressbuf[7] = 'C';

  uint32_t *network_length_p = (uint32_t *)(&(compressbuf[8]));
  *network_length_p = htonl(compressed_size);

  free(iobuf_p->outbuf);
  iobuf_p->outbuf = compressbuf;
  iobuf_p->outbuf_size = to_alloc;
  iobuf_p->outbuf_consumed = compressed_size + 12;

  size_t written = 0, to_write = iobuf_p->outbuf_consumed;

  while (written < to_write) {
    size_t left_to_write = min(to_write - written, (size_t)PR_INT32_MAX);
    PRInt32 count = PR_Write(iobuf_p->nsprconn, &(iobuf_p->outbuf[written]), (PRInt32)left_to_write);
    if (count < 0) {
      const PRErrorCode err = PR_GetError();
      error(3, 0, "TLS write error: NSPR error code %d: %s", err, PR_ErrorToName(err));
    }
    written += count;
  }

  //fprintf(stderr, "SENT %d frames (%lu bytes)\n", iobuf_p->outbuf_data_queue, (unsigned long)(iobuf_p->outbuf_consumed));

  iobuf_p->outbuf_consumed = 0;
  iobuf_p->outbuf_data_queue = 0;
}

void
write_buf_to_iobuf(struct iobuf *iobuf_p, const uint8_t *buf, size_t size) {
  size_t written = 0, to_write = size;

  while (written < to_write) {
    if (iobuf_p->outbuf_size == iobuf_p->outbuf_consumed) {
      size_t newsize = iobuf_p->outbuf_size * 2;
      uint8_t *newbuf = realloc(iobuf_p->outbuf, newsize);
      if (newbuf == NULL) errx("Allocation failure.");
      iobuf_p->outbuf = newbuf;
      iobuf_p->outbuf_size = newsize;
    }

    size_t count = min(iobuf_p->outbuf_size, to_write - written);
    memcpy((void *)(&iobuf_p->outbuf[iobuf_p->outbuf_consumed]), &buf[written], count);
    iobuf_p->outbuf_consumed += count;
    written += count;
  }
}

void
write_buf_to_iobuf_at(struct iobuf *iobuf_p, const uint8_t *buf, size_t size, size_t position) {
  if (position + size > iobuf_p->outbuf_consumed) abort();
  memcpy((void *)(&iobuf_p->outbuf[position]), buf, size);
}

void
peek_iobuf_at(struct iobuf *iobuf_p, uint8_t *buf, size_t size, size_t position) {
  if (position + size > iobuf_p->outbuf_consumed) abort();
  memcpy(buf, (void *)(&iobuf_p->outbuf[position]), size);
}

uint32_t
read_network_long_from_iobuf(struct iobuf *iobuf_p) {
  uint32_t network_long;
  read_buf_from_iobuf(iobuf_p, (uint8_t *)(&network_long), 4);
  return ntohl(network_long);
}

void
write_network_long_to_iobuf(struct iobuf *iobuf_p, uint32_t value) {
  uint32_t network_long;
  network_long = htonl(value);
  write_buf_to_iobuf(iobuf_p, (uint8_t *)(&network_long), 4);
}

void
add_network_long_to_iobuf_at(struct iobuf *iobuf_p, uint32_t add, size_t position) {
  uint32_t network_long;
  peek_iobuf_at(iobuf_p, (uint8_t *)(&network_long), 4, position);
  uint32_t value = ntohl(network_long);
  value += add;
  network_long = htonl(value);
  write_buf_to_iobuf_at(iobuf_p, (uint8_t *)(&network_long), 4, position);
}

uint32_t
read_lumberjack_ack(struct iobuf *iobuf_p) {
  uint8_t lumberjack_framehead[2];
  read_buf_from_iobuf(iobuf_p, &lumberjack_framehead[0], 2);
  if (lumberjack_framehead[0] == '1' &&
      lumberjack_framehead[1] == 'A') {
    return read_network_long_from_iobuf(iobuf_p);
  } else {
    // Don't know the size of any other frame types.
    errx("Lumberjack protocol error");
  }
}

void
begin_lumberjack_string(struct iobuf *iobuf_p) {
  // record where the string length value is
  iobuf_p->outbuf_string_length_pos = iobuf_p->outbuf_consumed;

  // and init the length
  write_network_long_to_iobuf(iobuf_p, 0);
}

void
extend_lumberjack_string(struct iobuf *iobuf_p, const char *string, size_t length) {
  if (length > UINT32_MAX) abort();
  // update the length
  add_network_long_to_iobuf_at(iobuf_p, length, iobuf_p->outbuf_string_length_pos);
  // extend the string
  write_buf_to_iobuf(iobuf_p, (const uint8_t *)string, length);
}

inline void
extend_buffer(void **buffer, size_t item_size, size_t *size_p, size_t required_size) {
  if (required_size >= SIZE_MAX / 2)
    errx("Integer overflow.");
  size_t new_size = max((size_t)SMALL_BUFFER_SIZE, *size_p);
  while (new_size < required_size)
    new_size *= 2;
  if (new_size == *size_p)
    return;

  *buffer = realloc(*buffer, item_size * (*size_p));
  if (*buffer == NULL) errx("Allocation failure.");
  *size_p = new_size;
}

// returned buffer is valid and writeable until next call to the
// function
inline void
mbstringbuf_to_wcstringbuf(wchar_t **buffer_p, size_t *buffer_size_p, const char *string, size_t mb_length) {
  int stateful_encoding __attribute__((unused));
  stateful_encoding = mbtowc(NULL, NULL, 0);
  size_t mb_index = 0;
  size_t wc_index = 0;
  while (mb_index < mb_length) {
    extend_buffer((void**)buffer_p, sizeof(wchar_t), buffer_size_p, wc_index + 1);
    int mb_consumed = mbtowc(&((*buffer_p)[wc_index++]), &(string[mb_index]), mb_length - mb_index);
    if (mb_consumed < 1)
      errx("Journal string error.");
    mb_index += mb_consumed;
  }
  (*buffer_p)[wc_index++] = 0;
}

inline void
buf_towlower(wchar_t *buf) {
  for(int i=0; buf[i] != 0; i++)
    buf[i] = towlower(buf[i]);
}
  
inline size_t
wcstringbuf_to_mbstringbuf(char **buffer_p, size_t *buffer_size_p, wchar_t *wcstring) {
  size_t required_mbstring_size = wcstombs(NULL, wcstring, 0) + 1;
  extend_buffer((void**)buffer_p, sizeof(char), buffer_size_p, required_mbstring_size);

  size_t ret = wcstombs(*buffer_p, wcstring, *buffer_size_p);
  if (ret == ((size_t)-1))
    errx("Journal string error.");

  return ret;
}

static char *mbstring_buffer = NULL;
static size_t mbstring_buffer_size = 0;

void
extend_lumberjack_wcstring(struct iobuf *iobuf_p, wchar_t *wcstring) {
  size_t size = wcstringbuf_to_mbstringbuf(&mbstring_buffer, &mbstring_buffer_size, wcstring);
  extend_lumberjack_string(iobuf_p, mbstring_buffer, size);
}

static wchar_t *wcstring_buffer = NULL;
static size_t wcstring_buffer_size = 0;

void
extend_lumberjack_string_tolower(struct iobuf *iobuf_p, const char *string, size_t length) {
  mbstringbuf_to_wcstringbuf(&wcstring_buffer, &wcstring_buffer_size, string, length);
  buf_towlower(wcstring_buffer);
  extend_lumberjack_wcstring(iobuf_p, wcstring_buffer);
}

void
write_lumberjack_string(struct iobuf *iobuf_p, const char *string) {
  begin_lumberjack_string(iobuf_p);
  extend_lumberjack_string(iobuf_p, string, strlen(string));
}

void
write_int_as_string_to_iobuf(struct iobuf *iobuf_p, uint64_t value) {
  char unix_ms_str[SMALL_BUFFER_SIZE];
  unix_ms_str[SMALL_BUFFER_SIZE-1] = '\0';

  snprintf(unix_ms_str, SMALL_BUFFER_SIZE-1, "%llu", (unsigned long long)value);

  write_lumberjack_string(iobuf_p, unix_ms_str);
}

void
write_unix_ms_date_to_iobuf(struct iobuf *iobuf_p, uint64_t timestamp_usec) {
  write_int_as_string_to_iobuf(iobuf_p, (uint64_t)(timestamp_usec / 1000));
}

void
write_lumberjack_frame_head(struct iobuf *iobuf_p, uint8_t version, uint8_t type) {
  uint8_t lumberjack_framehead[2];

  lumberjack_framehead[0] = version;
  lumberjack_framehead[1] = type;

  write_buf_to_iobuf(iobuf_p, lumberjack_framehead, 2);
}

void
start_lumberjack_data_frame(struct iobuf *iobuf_p, uint32_t sequence_number) {
  iobuf_p->outbuf_data_queue++;
  write_lumberjack_frame_head(iobuf_p, '1', 'D');
  write_network_long_to_iobuf(iobuf_p, sequence_number);

  // record where the field count value is
  iobuf_p->outbuf_data_field_count_pos = iobuf_p->outbuf_consumed;

  // and init the count
  write_network_long_to_iobuf(iobuf_p, 0);
}

void
lumberjack_data_inc_field_count(struct iobuf *iobuf_p) {
  add_network_long_to_iobuf_at(iobuf_p, 1, iobuf_p->outbuf_data_field_count_pos);
}

int
flush_lumberjack_data(struct iobuf *iobuf_p, int force) {
  if (iobuf_p->outbuf_data_queue > 0 && (force || iobuf_p->outbuf_consumed >= iobuf_p->outbuf_size / 2)) {
    lumberjack_package_frames(iobuf_p); // flush cleanly at frame end
    while (!poll_iobuf(iobuf_p, 2)) {}
    read_lumberjack_ack(iobuf_p); // TODO we ignore the value
    return 1;
  }
  return 0;
}

void
send_journal_entry_field_through_lumberjack(struct iobuf *iobuf_p, const void *data, size_t length) {
  const char *keyvalue = (char *)data;

  // separate the key and value
  const char *separator = strchr(keyvalue, '=');
  if (!separator) abort();
  size_t key_length = separator - keyvalue;

  const char *value = &(separator[1]);
  size_t value_length = length - key_length - 1;

  // _SOURCE_REALTIME_TIMESTAMP -> milliseconds -> source_timestamp

  if (strncmp(keyvalue, "_SOURCE_REALTIME_TIMESTAMP=", 27) == 0) {
    // send key
    lumberjack_data_inc_field_count(iobuf_p);
    write_lumberjack_string(iobuf_p, "source_timestamp");
    // send value
    uint64_t source_timestamp_usec = (uint64_t)atoll(value);
    write_unix_ms_date_to_iobuf(iobuf_p, source_timestamp_usec);
  }

  // _HOSTNAME -> shorten and lowercase value -> host

  static char *short_host_chars = "0123456789-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static char *first_host_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

  if (value_length > 0 && strncmp(keyvalue, "_HOSTNAME=", 10) == 0 && strchr(first_host_chars, value[0]) != NULL) {
    size_t short_host_length = 1;
    while (short_host_length < value_length && strchr(short_host_chars, value[short_host_length]) != NULL)
      short_host_length++;

    if (short_host_length == value_length || value[short_host_length] == '.') {
      // send key
      lumberjack_data_inc_field_count(iobuf_p);
      write_lumberjack_string(iobuf_p, "host");
      // send value
      begin_lumberjack_string(iobuf_p);
      extend_lumberjack_string_tolower(iobuf_p, value, short_host_length);
    }
  }

  // MESSAGE -> line
  // _SOURCE_REALTIME_TIMESTAMP -> source_realtime_timestamp
  // __(.*) -> lowercase key -> journal_\1
  // _(.*) -> lowercase key -> \1
  // (.*) -> \1

  // send key
  lumberjack_data_inc_field_count(iobuf_p);
  if (strncmp(keyvalue, "MESSAGE=", 8) == 0) {
    write_lumberjack_string(iobuf_p, "line");
  } else if (strncmp(keyvalue, "_SOURCE_REALTIME_TIMESTAMP=", 27) == 0) {
    write_lumberjack_string(iobuf_p, "source_realtime_timestamp");
  } else if (strncmp(keyvalue, "_", 1) == 0) {
    begin_lumberjack_string(iobuf_p);
    if (strncmp(keyvalue, "__", 2) == 0) {
      // __FOO -> journal_foo
      extend_lumberjack_string(iobuf_p, "journal", 7);
    }
    // skip the first character ('_'), lowercase the rest
    extend_lumberjack_string_tolower(iobuf_p, &(keyvalue[1]), key_length - 1);
  } else {
    begin_lumberjack_string(iobuf_p);
    extend_lumberjack_string(iobuf_p, keyvalue, key_length);
  }

  // send value
  begin_lumberjack_string(iobuf_p);
  extend_lumberjack_string(iobuf_p, value, value_length);
}

void
send_journal_entry_through_lumberjack(sd_journal *journal, uint64_t journal_realtime_timestamp_usec, struct iobuf *iobuf_p, uint32_t sequence_number) {
  start_lumberjack_data_frame(iobuf_p, sequence_number);

  // send key + value
  lumberjack_data_inc_field_count(iobuf_p);
  write_lumberjack_string(iobuf_p, "type");
  write_lumberjack_string(iobuf_p, "journal");

  // __REALTIME_TIMESTAMP -> milliseconds -> timestamp
  lumberjack_data_inc_field_count(iobuf_p);
  write_lumberjack_string(iobuf_p, "timestamp");
  write_unix_ms_date_to_iobuf(iobuf_p, journal_realtime_timestamp_usec);

  // __REALTIME_TIMESTAMP -> journal_realtime_timestamp
  lumberjack_data_inc_field_count(iobuf_p);
  write_lumberjack_string(iobuf_p, "journal_realtime_timestamp");
  write_int_as_string_to_iobuf(iobuf_p, journal_realtime_timestamp_usec);

  const void *data;
  size_t length;

  SD_JOURNAL_FOREACH_DATA(journal, data, length) {
    send_journal_entry_field_through_lumberjack(iobuf_p, data, length);
  }
}

void
send_journal_through_lumberjack(sd_journal *journal, struct iobuf *iobuf_p, int persistent, int stateless, char *acked_cursor) {
  uint32_t sent_sequence_number = 0;

  int persistent_update = 0;
  uint64_t last_persistent_update = 0;

  int cont = 1;

  while(cont) {
    int reached_end = 1;

    if (sd_journal_next(journal) > 0) {
      reached_end = 0;

      uint64_t journal_realtime_timestamp_usec;
      int res = sd_journal_get_realtime_usec(journal, &journal_realtime_timestamp_usec);
      if (res) abort();

      send_journal_entry_through_lumberjack(journal, journal_realtime_timestamp_usec, iobuf_p, ++sent_sequence_number);

      uint64_t truncated_time = journal_realtime_timestamp_usec & ~(time_t)0xfffffff;
      if (truncated_time > last_persistent_update) {
	// About every five minutes of records.
	last_persistent_update = truncated_time;
	persistent_update = 1;
      }
    }

    // If reached the end of the journal, force a flush and wait for the ack.
    // Else, there might be a flush anyway depending on buffer usage.
    int acked = flush_lumberjack_data(iobuf_p, reached_end);
    if (acked) {
      if (acked_cursor) free(acked_cursor);
      sd_journal_get_cursor(journal, &acked_cursor);
      if (!stateless) {
	save_cursor(RUNTIME_CURSOR_FILE, acked_cursor);
	if (persistent && persistent_update)
	  save_cursor(PERSISTENT_CURSOR_FILE, acked_cursor);
	persistent_update = 0;
      }
    }

    if (reached_end) {
      // We reached the end of the journal, sleep until something happens.
      struct inotify_event *event = inotifytools_next_event(-1);

      //inotifytools_printf( event, "%T %w%f %e\n" );

      // what's the proper API for checking the type?
      char eventtype[30];
      eventtype[29] = '\0';
      inotifytools_snprintf( eventtype, 29, event, "%e" );
      if (strcmp(eventtype, "CREATE") == 0) {
	// The journal was rotated, need to watch the new file and reopen the journal.

	persistent = watch_journal_paths();

	sd_journal_close(journal);
	int res = sd_journal_open(&journal, 0);
	if (res)
	  errx("Journal error");
	sd_journal_seek_cursor(journal, acked_cursor);
      }
    }
  }
}

void
open_and_stream_journal(char *host, char *port, int stateless) {
  int persistent = watch_journal_paths();

  sd_journal *journal;
  int res = sd_journal_open(&journal, 0);
  if (res)
    errx("Journal error");

  char *acked_cursor = NULL;

  // The runtime file, if it exists, should be at least as up to date as the persistent file.
  acked_cursor = load_cursor(RUNTIME_CURSOR_FILE);
  if (!acked_cursor)
    acked_cursor = load_cursor(PERSISTENT_CURSOR_FILE);

  if (acked_cursor)
    sd_journal_seek_cursor(journal, acked_cursor);

  struct iobuf *iobuf_p = iobuf_connect_tls(host, port);

  sd_notify(0, "READY=1");

  send_journal_through_lumberjack(journal, iobuf_p, persistent, stateless, acked_cursor);

  // this will never be reached

  iobuf_close(iobuf_p);

  sd_journal_close(journal);
}

int
main(int argc, char **argv)
{
  verbose_flag = 0;
  help_flag = 0;

  int stateless = 0;
  char *host = NULL;
  char *port = NULL;
  char *certdb = NULL;

  int c;

  while (1) {
    static struct option long_options[] =
      {
	{"verbose", no_argument, &verbose_flag, 1},
	{"stateless", no_argument, 0, 0},
	{"host",      required_argument, 0, 0},
	{"port",      required_argument, 0, 0},
	{"certdb",    required_argument, 0, 0},
	{"help", no_argument, &help_flag, 1},
	{0, 0, 0, 0}
      };
    int option_index = 0;

    c = getopt_long (argc, argv, "s:H:P:C:h",
		     long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
      {
      case 0:
	if (long_options[option_index].flag != 0)
	  break;
	if (option_index == 1)
	  stateless = 1;
	if (option_index == 2)
	  host = strdup(optarg);
	if (option_index == 3)
	  port = strdup(optarg);
	if (option_index == 4)
	  certdb = strdup(optarg);
	break;

      case 's':
	stateless = 1;
	break;

      case 'H':
	host = strdup(optarg);
	break;

      case 'P':
	host = strdup(optarg);
	break;

      case 'C':
	certdb = strdup(optarg);
	break;

      case 'h':
	help_flag = 1;
	break;

      case '?':
	break;

      default:
	usage();
	exit(1);
      }
  }

  if (optind < argc) {
    usage();
    exit(1);
  }

  if (help_flag || host == NULL || port == NULL || certdb == NULL) {
    usage();
    exit(0);
  }

  nspr_tls_init(certdb);

  if (inotifytools_initialize() == 0) {
    error(3, 0, "%s", strerror(inotifytools_error()));
  }

  open_and_stream_journal(host, port, stateless);

  exit(0);
}

