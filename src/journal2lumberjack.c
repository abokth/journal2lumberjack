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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <systemd/sd-journal.h>
#include <zlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inotifytools/inotifytools.h>
#include <inotifytools/inotify.h>

#define min(a,b)				\
  ({ __typeof__ (a) _a = (a);			\
    __typeof__ (b) _b = (b);			\
    _a < _b ? _a : _b; })

static int verbose_flag;
static int help_flag;

void
usage() {
  fprintf(stderr, "Usage: journal2lumberjack [--stateless] --host <lumberjack host:port> --cafile <lumbjerjack CA>\n");
}

#define STREAM_BUFFER_SIZE 1048576

struct iobuf {
  uint8_t *inbuf;
  uint8_t *outbuf;
  size_t inbuf_start; // first used byte
  size_t inbuf_consumed, outbuf_consumed; // first free byte
  size_t inbuf_size, outbuf_size;
  int outbuf_data_queue;
  int in, out;
};

// Returns true if there are at least this much available to read,
// this works with both blocking and non-blocking file descriptors.
int
poll_iobuf(struct iobuf *iobuf_p, size_t bytes) {
  if ( (iobuf_p->inbuf_consumed - iobuf_p->inbuf_start) < bytes ) {
    ssize_t count = read(iobuf_p->in, (void *)(&iobuf_p->inbuf[iobuf_p->inbuf_consumed]), iobuf_p->inbuf_size - iobuf_p->inbuf_consumed);
    if (count <= 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
	abort();
      }
      count = 0;
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
    ssize_t count = read(iobuf_p->in, (void *)(&buf[has_read]), to_read - has_read);
    if (count < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
	continue;
      } else {
	abort();
      }
      count = 0;
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
  if (compressbuf == NULL) abort();
  uLong compressed_size = to_alloc - 12;

  // Set window size to the number of queued data frames.
  compressbuf[0] = '1';
  compressbuf[1] = 'W';
  uint32_t *window_size_p = (uint32_t *)(&(compressbuf[2]));
  *window_size_p = htonl(iobuf_p->outbuf_data_queue);

  err = compress(&compressbuf[12], &compressed_size, (const Bytef*)(iobuf_p->outbuf), (uLong)(iobuf_p->outbuf_consumed));
  if (err != Z_OK) abort();

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
    ssize_t count = write(iobuf_p->out, &(iobuf_p->outbuf[written]), to_write - written);
    if (count < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
	continue;
      } else {
	abort();
      }
      count = 0;
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
      if (newbuf == NULL) abort();
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
write_network_long_to_iobuf_at(struct iobuf *iobuf_p, uint32_t value, size_t position) {
  uint32_t network_long;
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
    abort();
  }
}

void
write_lumbjerjack_string(struct iobuf *iobuf_p, const char *string) {
  size_t l = strlen(string);
  write_network_long_to_iobuf(iobuf_p, l);
  write_buf_to_iobuf(iobuf_p, (const uint8_t *)string, l);
}

void
write_lumberjack_frame_head(struct iobuf *iobuf_p, uint8_t version, uint8_t type) {
  uint8_t lumberjack_framehead[2];

  lumberjack_framehead[0] = version;
  lumberjack_framehead[1] = type;

  write_buf_to_iobuf(iobuf_p, lumberjack_framehead, 2);
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

#define RUNTIME_CURSOR_FILE "/run/journal-export-acked-cursor"
#define PERSISTENT_CURSOR_FILE "/var/lib/journal-export-acked-cursor"

void
save_cursor(const char *filename, const char *acked_cursor) {
  FILE *statefile = fopen(filename, "w");
  if (statefile == NULL) abort();
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
    if (res == 0) abort();
  }
    
  res = stat(PERSISTENT_JOURNAL_DIR, &s);
  if (res == 0) {
    found_journal = 1;
    res = inotifytools_watch_recursively(PERSISTENT_JOURNAL_DIR, IN_MODIFY | IN_CREATE);
    if (res == 0) abort();
    persistent = 1;
  }

  if (!found_journal)
    abort();

  return persistent;
}

int
main(int argc, char **argv)
{
  verbose_flag = 0;
  help_flag = 0;

  int stateless = 0;
  char *host = NULL;
  char *cafile = NULL;

  int c;

  while (1) {
    static struct option long_options[] =
      {
	{"verbose", no_argument, &verbose_flag, 1},
	{"stateless", no_argument, 0, 0},
	{"host",      required_argument, 0, 0},
	{"cafile",    required_argument, 0, 0},
	{"help", no_argument, &help_flag, 1},
	{0, 0, 0, 0}
      };
    int option_index = 0;

    c = getopt_long (argc, argv, "s:H:C:h",
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
	  cafile = strdup(optarg);
	break;

      case 's':
	stateless = 1;
	break;

      case 'H':
	host = strdup(optarg);
	break;

      case 'C':
	cafile = strdup(optarg);
	break;

      case 'h':
	help_flag = 1;
	break;

      case '?':
	break;

      default:
	usage();
	abort();
      }
  }

  if (optind < argc) {
    usage();
    abort();
  }

  if (help_flag || host == NULL || cafile == NULL) {
    usage();
    exit(0);
  }

  char *sslstring = NULL;
  if(asprintf(&sslstring, "SSL:%s,cafile=%s,verify=0", host, cafile) <= 0) abort();

  int tocat[2], fromcat[2];

  if (pipe2(tocat, 0)) abort();
  if (pipe2(fromcat, 0)) abort();

  // Using socat for SSL is stupid but it works.

  int cpid = fork();
  if (cpid == -1) abort();

  if (cpid == 0) {
    // socat here
    close(tocat[1]);
    close(fromcat[0]);
    dup2(tocat[0],0); // socat stdin
    close(tocat[0]);
    dup2(fromcat[1],1); // socat stdout
    close(fromcat[1]);
    execl("/usr/bin/socat", "socat", "-", sslstring, NULL);
    abort();
  }

  close(tocat[0]);
  close(fromcat[1]);

  struct iobuf iobuf;
  iobuf.in = fromcat[0];
  iobuf.out = tocat[1];
  iobuf.inbuf = calloc(STREAM_BUFFER_SIZE, sizeof(uint8_t));
  iobuf.outbuf = calloc(STREAM_BUFFER_SIZE, sizeof(uint8_t));
  iobuf.inbuf_size = STREAM_BUFFER_SIZE;
  iobuf.outbuf_size = STREAM_BUFFER_SIZE;
  iobuf.inbuf_start = 0;
  iobuf.inbuf_consumed = 0;
  iobuf.outbuf_consumed = 0;
  iobuf.outbuf_data_queue = 0;

  uint32_t sent_sequence_number = 0;

  char timestamp_rfc3339_a[100];
  timestamp_rfc3339_a[99] = '\0';
  char timestamp_rfc3339_b[100];
  timestamp_rfc3339_b[99] = '\0';

  char timestamp_msec[100];
  timestamp_msec[99] = '\0';


  if (inotifytools_initialize() == 0)
    fprintf(stderr, "%s\n", strerror( inotifytools_error()));

  int persistent = watch_journal_paths();

  int res;

  sd_journal *journal;

  res = sd_journal_open(&journal, 0);
  if (res) {
    abort();
  }

  char *acked_cursor = NULL;

  // The runtime file, if it exists, should be at least as up to date as the persistent file.
  FILE *statefile = fopen(RUNTIME_CURSOR_FILE, "r");
  if (!statefile)
    statefile = fopen(PERSISTENT_CURSOR_FILE, "r");
  if (statefile) {
    char readbuf[1024];
    readbuf[1023] = '\0';
    if (fgets(readbuf, 1023, statefile) != NULL)
      acked_cursor = strdup(readbuf);
    fclose(statefile);
  }

  sd_journal_seek_cursor(journal, acked_cursor);

  int persistent_update = 0;

  time_t last_persistent_update = 0;

  int cont = 1;

  while(cont) {
    int reached_end = 1;

    if (sd_journal_next(journal) > 0) {
      reached_end = 0;

      uint64_t timestamp_usec;
      int res = sd_journal_get_realtime_usec(journal, &timestamp_usec);
      if (res) abort();

      time_t timestamp_time_t = timestamp_usec / 1000000;

      time_t truncated_time = timestamp_time_t & ~(time_t)0xff;
      if (truncated_time > last_persistent_update) {
	last_persistent_update = truncated_time;
	persistent_update = 1;
      }

      struct tm timestamp_tm;
      gmtime_r(&timestamp_time_t, &timestamp_tm);

      strftime(timestamp_rfc3339_a, 99, "%FT%T", &timestamp_tm);
      snprintf(timestamp_rfc3339_b, 99, ".%03u", (int)(timestamp_usec % 1000000) / 1000);

      size_t timestamp_rfc3339_a_len = strlen(timestamp_rfc3339_a);
      size_t timestamp_rfc3339_b_len = strlen(timestamp_rfc3339_b);

      snprintf(timestamp_msec, 99, "%ld", (long)(timestamp_usec / 1000));

      //fprintf(stderr, "%s%sZ\n", timestamp_rfc3339_a, timestamp_rfc3339_b);

      const void *data;
      size_t length;
      int num_fields = 0;

      iobuf.outbuf_data_queue++;
      write_lumberjack_frame_head(&iobuf, '1', 'D');
      write_network_long_to_iobuf(&iobuf, ++sent_sequence_number);

      // record where the dummy field count value is
      size_t num_fields_pos = iobuf.outbuf_consumed;
      write_network_long_to_iobuf(&iobuf, 0); // dummy value

      // send key + value
      num_fields++;
      write_lumbjerjack_string(&iobuf, "type");
      write_lumbjerjack_string(&iobuf, "journal");

      // send key
      num_fields++;
      write_lumbjerjack_string(&iobuf, "timestamp");
      // send value
      write_network_long_to_iobuf(&iobuf, timestamp_rfc3339_a_len + timestamp_rfc3339_b_len + 1);
      write_buf_to_iobuf(&iobuf, (uint8_t *)timestamp_rfc3339_a, timestamp_rfc3339_a_len);
      write_buf_to_iobuf(&iobuf, (uint8_t *)timestamp_rfc3339_b, timestamp_rfc3339_b_len);
      write_buf_to_iobuf(&iobuf, (uint8_t *)"Z", 1);

      // send key + value
      num_fields++;
      write_lumbjerjack_string(&iobuf, "__REALTIME_TIMESTAMP");
      write_lumbjerjack_string(&iobuf, timestamp_msec);

      SD_JOURNAL_FOREACH_DATA(journal, data, length) {
	num_fields++;

	// separate the key and value
	const char *separator = strchr(data, '=');
	if (!separator) abort();
	size_t key_length = ((const void *)separator) - data;

	const char *value = &(separator[1]);
	size_t value_length = length - key_length - 1;

	// send key
	if (strncmp(data, "MESSAGE=", 8) == 0) {
	  write_lumbjerjack_string(&iobuf, "line");
	} else if (strncmp(data, "_HOSTNAME=", 10) == 0) {
	  write_lumbjerjack_string(&iobuf, "host");
	} else {
	  write_network_long_to_iobuf(&iobuf, key_length);
	  write_buf_to_iobuf(&iobuf, data, key_length);
	}

	// send value
	write_network_long_to_iobuf(&iobuf, value_length);
	write_buf_to_iobuf(&iobuf, (uint8_t *)value, value_length);
      }

      // replace the dummy value with the proper one before sending
      write_network_long_to_iobuf_at(&iobuf, num_fields, num_fields_pos);
    }

    int acked = flush_lumberjack_data(&iobuf, reached_end);
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
	if (res) {
	  abort();
	}
	sd_journal_seek_cursor(journal, acked_cursor);
      }
    }
  }

  sd_journal_close(journal);
  exit(0);
}

