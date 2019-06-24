/* for `asprintf` */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>

#include "sha3.h"

typedef void (*init_t)(void *);
typedef void (*update_t)(void *, void *, size_t);
typedef void (*final_t)(void *, void *);

typedef struct {
  char *name;
  size_t digest_size, ctx_size;
  init_t init;
  update_t update;
  final_t final;
} algo_t;

algo_t algo_sha1 =
  {"SHA-1", 20, sizeof(SHA_CTX),
   (init_t)SHA1_Init,
   (update_t)SHA1_Update,
   (final_t)SHA1_Final};

algo_t algo_sha224 =
  {"SHA-224", 28, sizeof(SHA256_CTX),
   (init_t)SHA224_Init,
   (update_t)SHA224_Update,
   (final_t)SHA224_Final};

algo_t algo_sha256 =
  {"SHA-256", 32, sizeof(SHA256_CTX),
   (init_t)SHA256_Init,
   (update_t)SHA256_Update,
   (final_t)SHA256_Final};

algo_t algo_sha384 =
  {"SHA-384", 48, sizeof(SHA512_CTX),
   (init_t)SHA384_Init,
   (update_t)SHA384_Update,
   (final_t)SHA384_Final};

algo_t algo_sha512 =
  {"SHA-512", 64, sizeof(SHA512_CTX),
   (init_t)SHA512_Init,
   (update_t)SHA512_Update,
   (final_t)SHA512_Final};

algo_t algo_md5 =
  {"MD5", 16, sizeof(MD5_CTX),
   (init_t)MD5_Init,
   (update_t)MD5_Update,
   (final_t)MD5_Final};

algo_t algo_md4 =
  {"MD4", 16, sizeof(MD4_CTX),
   (init_t)MD4_Init,
   (update_t)MD4_Update,
   (final_t)MD4_Final};

algo_t algo_ripemd160 =
  {"RIPEMD-160", 20, sizeof(RIPEMD160_CTX),
   (init_t)RIPEMD160_Init,
   (update_t)RIPEMD160_Update,
   (final_t)RIPEMD160_Final};

algo_t algo_sha3_256 =
  {"SHA3-256", 32, sizeof(sha3_context),
   (init_t)sha3_Init256,
   (update_t)sha3_Update,
   (final_t)sha3_Finalize};

algo_t algo_sha3_384 =
  {"SHA3-384", 32, sizeof(sha3_context),
   (init_t)sha3_Init384,
   (update_t)sha3_Update,
   (final_t)sha3_Finalize};

algo_t algo_sha3_512 =
  {"SHA3-512", 32, sizeof(sha3_context),
   (init_t)sha3_Init512,
   (update_t)sha3_Update,
   (final_t)sha3_Finalize};

const struct {
  char *name;
  algo_t *algo;
} algos[] = {

  {"sha1", &algo_sha1},
  {"sha-1", &algo_sha1},
  {"SHA1", &algo_sha1},
  {"SHA-1", &algo_sha1},

  {"sha224", &algo_sha224},
  {"sha-224", &algo_sha224},
  {"SHA224", &algo_sha224},
  {"SHA-224", &algo_sha224},

  {"sha256", &algo_sha256},
  {"sha-256", &algo_sha256},
  {"SHA256", &algo_sha256},
  {"SHA-256", &algo_sha256},

  {"sha384", &algo_sha384},
  {"sha-384", &algo_sha384},
  {"SHA384", &algo_sha384},
  {"SHA-384", &algo_sha384},

  {"sha512", &algo_sha512},
  {"sha-512", &algo_sha512},
  {"SHA512", &algo_sha512},
  {"SHA-512", &algo_sha512},

  {"md5", &algo_md5},
  {"MD5", &algo_md5},

  {"md4", &algo_md4},
  {"MD4", &algo_md4},

  {"ripemd-160", &algo_ripemd160},
  {"ripemd160", &algo_ripemd160},
  {"RIPEMD-160", &algo_ripemd160},
  {"RIPEMD160", &algo_ripemd160},

  {"sha3-256", &algo_sha3_256},
  {"SHA3-256", &algo_sha3_256},

  {"sha3-384", &algo_sha3_384},
  {"SHA3-384", &algo_sha3_384},

  {"sha3-512", &algo_sha3_512},
  {"SHA3-512", &algo_sha3_512},

  {NULL, NULL},
};

/* unsigned bignum; big endian so `memcmp` can be used to compare */
#define bn_size (int)opts.algo->digest_size
typedef unsigned char* bn_t;

struct {
  algo_t *algo;
  size_t num_threads;
  bool verbose;
  unsigned long long max_tries;
  time_t timeout;
  bool is_ccc;
  union {
    struct {
      char *mask;
      unsigned char *prefix, *suffix;
      char add_chars[0x100], rem_chars[0x100];
      size_t pow_len;
      bool big_endian;
      bool is_binary;
      unsigned char alphabet[0x100];
      unsigned char *zmask, *omask;
    };
    struct {
      char *challenge;
      unsigned long long hardness;
      bn_t target;
    };
  };
} opts;

pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
char *g_pow = NULL;
unsigned long long g_progress;

/* This variable is only ever changed from false to true and are read
 * continuously so no locking is necessary
 */
bool g_quit = false;

#define DEFAULT_MAX_TRIES ((unsigned long long)1<<40)

#define DEFAULT_ALPHABET                                            \
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"  \
  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

#define CLASS_LETTER                            \
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define CLASS_UPPER                             \
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CLASS_LOWER                             \
  "abcdefghijklmnopqrstuvwxyz"
#define CLASS_ALNUM                             \
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define CLASS_ALNUMU                            \
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CLASS_ALNUML                            \
  "abcdefghijklmnopqrstuvwxyz0123456789"
#define CLASS_HEX                               \
  "ABCDEFabcdef0123456789"
#define CLASS_HEXU                              \
  "ABCDEF0123456789"
#define CLASS_HEXL                              \
  "abcdef0123456789"
#define CLASS_DIGIT                             \
  "0123456789"
#define CLASS_SYMBOL                            \
  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
#define CLASS_WS                                \
  "\t\n\x0b\x0c\r "

struct {
  char *name;
  char *class;
} classes[] = {
  {"letters", CLASS_LETTER},
  {"letter", CLASS_LETTER},
  {"alphas", CLASS_LETTER},
  {"alpha", CLASS_LETTER},

  {"upper", CLASS_UPPER},

  {"lower", CLASS_LOWER},

  {"alphanum", CLASS_ALNUM},
  {"alphanum-upper", CLASS_ALNUMU},
  {"alphanum-lower", CLASS_ALNUML},
  {"alnum", CLASS_ALNUM},
  {"alnum-upper", CLASS_ALNUMU},
  {"alnum-lower", CLASS_ALNUML},

  {"hex", CLASS_HEX},
  {"hex-upper", CLASS_HEXU},
  {"hex-lower", CLASS_HEXL},

  {"digits", CLASS_DIGIT},
  {"digit", CLASS_DIGIT},
  {"numbers", CLASS_DIGIT},
  {"number", CLASS_DIGIT},

  {"symbols", CLASS_SYMBOL},
  {"symbol", CLASS_SYMBOL},

  {"whitespace", CLASS_WS},

  {NULL, NULL}
};

void usage(char *prog) {
  size_t i;
  algo_t *prev_algo;

  fprintf(stderr,
          "usage: %1$s [options] <algorithm> <digest mask>\n"
          "       %1$s --ccc [options] <challenge>\n"
          "\n"
          "Options:\n"
          "  --CLASS\n"
          "    Add CLASS to alphabet.  The default alphabet is used if no classes or\n"
          "    characters are given.  The default alphabet is every byte except 0 when\n"
          "    --binary is given and the printable ASCII characters otherwise.\n"
          "\n"
          "  --character|-c <character>|<byte value>\n"
          "    Add character to alphabet.  Examples: -cA, -c0x0a, -c10.\n"
          "\n"
          "  --no-CLASS, --no-<character>, --no-<byte value>\n"
          "    Remove CLASS or character from the alphabet.  Examples: --no-letters,\n"
          "    --no-A, --no-0x0a, --no-10.  NB: e.g. --no-1 is equivalent to --no-0x31\n"
          "    *NOT* --no-0x01.\n"
          "\n"
          "  --prefix|-p <string>, --suffix|-s <string>\n"
          "    Specifies the required prefix/suffix of a PoW.  None, either or both can\n"
          "    be given.  The suffix/prefix should be hex-encoded when --binary is given.\n"
          "\n"
          "  --binary|-b\n"
          "    In binary mode the pattern and PoW are hex-encoded and the default\n"
          "    alphabet contains all bytes except 0.\n"
          "\n"
          "  --endian|-e big|b|little|l\n"
          "    Specifies that the mask is given in little/big enddian.  Default: big.\n"
          "\n"
          "  --length|-n <number>, --min-length <number>, --max-length <number>\n"
          "    Sets the (minimal/maximal) length of the PoW.  Last occurrence takes\n"
          "    precence, e.g. `--length 10 --max-length 20` is equivalent to\n"
          "    `--min-length 10 --max-length 20` and `--max-length 20 --length 10` is\n"
          "    equivalent to just `--length 10`.\n"
          "\n"
          "  --ccc\n"
          "    Solve CCC style PoW (https://35c3ctf.ccc.ac/uploads/pow.py).  This option is\n"
          "    incompatible with all of the options above (i.e. they will be ignored).\n"
          "\n"
          "  --threads|-J <number>\n"
          "    Sets the number of threads to spawn.  Default: number of cores.\n"
          "\n"
          "  --max-tries <millions>\n"
          "    Sets the maximum number of digests to compute (total, not per thread)\n"
          "    before giving up.  Default: approximately one trillion.  NB: Length\n"
          "    restrictions take precedent over this setting; if the maximal length is\n"
          "    set to e.g. 4 and the default alphabet is used, then the maximum number of\n"
          "    tries will be 78074896 (= 94^4).\n"
          "\n"
          "  --timeout|-t <seconds>\n"
          "    Sets the maximum time to run before giving up.  Default: forever.\n"
          "\n"
          "  --verbose|-v\n"
          "    Be chatty.  The PoW (if one is found) is written to STDOUT.  Everything\n"
          "    else goes to STDERR.\n"
          "\n"
          "  --help|-h\n"
          "    You're reading it.\n"
          "\n"
          "Character classes:\n"
          "  letter, letters, alpha, alphas:\n"
          "    ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\n"
          "  upper:\n"
          "    ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
          "  lower:\n"
          "    abcdefghijklmnopqrstuvwxyz\n"
          "  alphanum, alnum:\n"
          "    ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\n"
          "  alphanum-upper, alnum-upper:\n"
          "    ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
          "  alphanum-lower, alnum-lower:\n"
          "    abcdefghijklmnopqrstuvwxyz0123456789\n"
          "  hex:\n"
          "    ABCDEFabcdef0123456789\n"
          "  hex-upper:\n"
          "    ABCDEF0123456789\n"
          "  hex-lower:\n"
          "    abcdef0123456789\n"
          "  digit, digits, number, numbers:\n"
          "    0123456789\n"
          "  symbol, symbols:\n"
          "    !\"#$%%&\'()*+,-./:;<=>?@[\\]^_`{|}~\n"
          "  whitespace:\n"
          "    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20\n"
          "\n"
          "Mask:\n"
          "  By default a mask specifies the most significant bits of the digest.  Use\n"
          "  \"-\" to specify that the rest of the mask specify the least significant\n"
          "  bits.  By default each digit of the mask correspond to a single bit.  With the\n"
          "  prefix \"0x\" each digit correspond to 4 bits given by a hexadecimal digit. The\n"
          "  prefix must be given for the most and least significant parts separately. The\n"
          "  character ? matches any value.  A digit may be followed by a repeat count\n"
          "  enclosed in curly braces.  Examples:\n"
          "    1{20}         : 20 leading 1's.  Matches fffff...\n"
          "    0xf{5}        : Equivalent to the previous\n"
          "    -0{16}        : 16 trailing 0's.  Matches ...0000\n"
          "    -0x0000       : Equivalent to the previous\n"
          "    1{12} combined with `--endian little`:\n"
          "                    Matches ...f?ff\n"
          "    -1111????1{8} : Equivalent to the previous\n"
          "    -0xf?ff       : Equivalent to the previous\n"
          "    1{12}-0{12}   : Matches fff...000\n"
          "    0xfff-0x000   : Equivalent to the previous\n"
          "\n"
          "Supported algorithms:\n", prog);

  prev_algo = NULL;
  for (i = 0; algos[i].name; i++) {
    if (algos[i].algo != prev_algo) {
      prev_algo = algos[i].algo;
      fprintf(stderr, " - %s\n", algos[i].algo->name);
    }
  }

  fprintf(stderr,
          "\n"
          "Examples:\n"
          "  $ pow --no-symbols --prefix POW_ sha1 1{20}\n"
          "  POW_heuAAA\n"
          "  $ pow --no-symbols sha1 1{20}\n"
          "  qX4KFq\n"
          "  $ pow --no-symbols --length 7 --prefix POW_ sha1 1{20} || echo \":'(\"\n"
          "  :'(\n"
          "  $ pow --no-symbols --length 8 --prefix POW_ sha1 1{20} || echo \":'(\"\n"
          "  POW_C3kB\n"
          "  $ pow --lower --prefix POW{ --suffix } sha1 1{12}-1{12}\n"
          "  POW{zzrglqlq}\n"
          "  $ pow --ccc 12345678_9nNMpkwGT4\n"
          "  3781679\n"
          );
  exit(EXIT_FAILURE);
}

#define die(fmt, args...)                       \
  do {                                          \
    fprintf(stderr, fmt, ## args);              \
    exit(EXIT_FAILURE);                         \
  } while (0)

void charset_union(char *a, char *b) {
  size_t i, j;
  for (j = 0; b[j]; j++) {
    for (i = 0; a[i]; i++) {
      if (a[i] == b[j]) {
        break;
      }
    }
    if (!a[i]) {
      a[i] = b[j];
      a[i + 1] = 0;
    }
  }
}

void charset_discard(char *a, char *b) {
  size_t i, j;
  for (j = 0; b[j]; j++) {
    for (i = 0; a[i]; i++) {
      if (a[i] == b[j]) {
        break;
      }
    }
    for (;a[i]; i++) {
      a[i] = a[i + 1];
    }
  }
}

static inline
unsigned int s2uint(char *str) {
  unsigned int out, base, d;
  char c, *p;

  p = str;

  if ('0' == *p) {
    p++;
    switch (*p) {

    case 'X':
    case 'x':
      base = 16;
      p++;
      break;

    case 'B':
    case 'b':
      base = 2;
      p++;
      break;

    default:
      base = 8;

    }
  } else {
    base = 10;
  }
  out = 0;

  while ((c = *p++)) {
    switch (c) {

    case '0'...'9':
      d = c - '0';
      break;

    case 'a'...'z':
      d = c - 'a' + 10;
      break;

    case 'A'...'Z':
      d = c - 'A' + 10;
      break;

    default:
      return 0;
    }
    if (d >= base) {
      return 0;
    }
    out = out * base + d;
  }

  return out;
}

char *unhex(char *str) {
  char *out;
  size_t i, j;
  char n1, n2;

#define unhex1(n, c)                            \
  do {                                          \
    switch (c) {                                \
    case '0'...'9':                             \
      n = c - '0';                              \
      break;                                    \
    case 'a'...'z':                             \
      n = c - 'a' + 10;                         \
      break;                                    \
    case 'A'...'Z':                             \
      n = c - 'A' + 10;                         \
      break;                                    \
    default:                                    \
      die("invalid hex-encoding: %s\n", str);   \
    }                                           \
  } while (0)

  if (strlen(str) % 2) {
    die("odd-length hex-encoding: %s\n", str);
  }

  out = malloc(strlen(str) * 2 + 1);

  for (i = 0, j = 0; str[i]; i += 2, j++) {
    unhex1(n1, str[i]);
    unhex1(n2, str[i + 1]);
    out[j] = (n1 << 4) | n2;
  }
  out[j] = 0;

#undef unhex1
  return out;
}

void parse_mask() {
  char *p;
  size_t i, j, n, len_head, len_tail,
    nbits = opts.algo->digest_size * 8;
  char m, d;
  bool has_tail, is_hex;
  unsigned char
    zmask[nbits],
    omask[nbits];

  memset(zmask, 0, nbits);
  memset(omask, 0, nbits);
  opts.zmask = calloc(opts.algo->digest_size, 1);
  opts.omask = calloc(opts.algo->digest_size, 1);

  /* Parse mask */
  i = 0;
  p = opts.mask;
  has_tail = false;
  is_hex = false;
  while (*p) {
    /* if (i >= nbits) { */
    /*   die("mask is larger than digest\n"); */
    /* } */

    /* Tail of mask? */
    if (!has_tail && '-' == *p) {
      has_tail = true;
      is_hex = false;
      len_head = i;
      p++;
    }

    /* Is mask in hexadecimal? */
    if (!is_hex && '0' == p[0] && 'x' == (p[1] | 0x20)) {
      is_hex = true;
      p += 2;
    }

    /* This mask bit/nibble. */
    m = *p++;

    /* Repetition */
    if ('{' == *p) {
      p++;
      n = 0;
      while ('}' != *p) {
        d = *p++;
        if ('0' > d || '9' < d) {
          die("invalid mask: %s\n", opts.mask);
        }
        n = n * 10 + d - '0';
      }
      p++;
    } else {
      n = 1;
    }

    /* Check mask length */
    if (i + n * (is_hex ? 4 : 1) >= nbits) {
      die("mask is larger than digest\n");
    }

    if ('?' != m) {
      /* Parse mask digit */
      if (is_hex) {
        switch (m) {
        case '0'...'9':
          m -= '0';
          break;
        case 'a'...'z':
          m -= 'a' - 10;
          break;
        case 'A'...'Z':
          m -= 'A' - 10;
          break;
        default:
          goto INVALID;
        }
      } else {
        switch (m) {
        case '0':
          m = 0;
          break;
        case '1':
          m = 1;
          break;
        default:
        INVALID:
          die("invalid mask: %s\n", opts.mask);
        }
      }
      /* Set mask bits */
      for (j = 0; j < n; j++) {
        if (is_hex) {
          (m & 8 ? omask : zmask)[i++] = 1;
          (m & 4 ? omask : zmask)[i++] = 1;
          (m & 2 ? omask : zmask)[i++] = 1;
        }
        (m & 1 ? omask : zmask)[i++] = 1;
      }
    } else {
      /* Skip wildcard bits */
      i += n * (is_hex ? 4 : 1);
    }

  }

  /* Move tail to end */
  if (has_tail) {
    len_tail = i - len_head;
    memmove(&zmask[nbits - len_tail], &zmask[len_head],
            len_tail);
    memset(&zmask[len_head], 0, nbits - len_head - len_tail);
    memmove(&omask[nbits - len_tail], &omask[len_head],
            len_tail);
    memset(&omask[len_head], 0, nbits - len_head - len_tail);
  }

  /* Compress mask to bytes */
  for (i = 0; i < nbits; i++) {
    if (opts.big_endian) {
      opts.zmask[i / 8] |= zmask[i] << (7 - i % 8);
      opts.omask[i / 8] |= omask[i] << (7 - i % 8);
    } else {
      opts.zmask[(nbits - 1 - i) / 8] |= \
        zmask[i] << (7 - i % 8);
      opts.omask[(nbits - 1 - i) / 8] |= \
        omask[i] << (7 - i % 8);
    }
  }
}

static inline
int bn_cmp(bn_t a, bn_t b) {
  return memcmp(a, b, bn_size);
}

void bn_sub(bn_t a, bn_t b) {
  int i, tmp, borrow = 0;
  for (i = bn_size - 1; i >= 0; i--) {
    tmp = a[i] - b[i] - borrow;
    a[i] = tmp & 0xff;
    borrow = tmp < 0;
  }
}

void bn_rshift1(bn_t x) {
  int i;
  for (i = bn_size - 1; i > 0; i--) {
    x[i] = (x[i] >> 1) | (x[i - 1] << 7);
  }
  x[i] >>= 1;
}

void bn_lshift1(bn_t x) {
  int i;
  for (i = 0; i < bn_size - 1; i++) {
    x[i] = (x[i] << 1) | (x[i + 1] >> 7);
  }
  x[i] <<= 1;
}

/* Calculates target := 2^digest_bits / hardness */
bn_t calculate_target(unsigned long long hardness) {
  bn_t target, x, y;
  int i;

  target = calloc(bn_size, 1);
  x = calloc(bn_size, 1);
  y = calloc(bn_size, 1);

  /* set initial divisor = hardness */
  for (i = bn_size - 1; hardness; i--) {
    y[i] = hardness & 0xff;
    hardness >>= 8;
  }

  /* left shift divisor as long as it will go */
  for (i = 0; !(y[0] & 0x80); i++) {
    bn_lshift1(y);
  }

  while (i >= 0) {
    bn_sub(x, y);
    target[bn_size - 1 - i / 8] |= 1 << (i & 7);
    do {
      i--;
      bn_rshift1(y);
    } while (bn_cmp(x, y) < 0);
  }

  free(y);
  free(x);
  return target;
}

void parse_args(int argc, char *argv[]) {
  int i, j;
  unsigned int n;
  size_t fixed_len, search_len, min_len, max_len;
  char *arg, *opt, *cls, shortopt[3] = {0}, cbuf[2] = {0};

  opts.is_ccc = false;

  /* CCC-style */
  opts.challenge = NULL;

  /* Non-CCC */
  opts.mask = NULL;
  opts.algo = NULL;
  opts.prefix = (unsigned char*)"";
  opts.suffix = (unsigned char*)"";
  opts.add_chars[0] = 0;
  opts.rem_chars[0] = 0;
  opts.pow_len = 0;
  opts.big_endian = true;
  opts.is_binary = false;

  /* General opts */
  opts.verbose = false;
  opts.num_threads = sysconf(_SC_NPROCESSORS_ONLN);
  opts.max_tries = DEFAULT_MAX_TRIES;
  opts.timeout = 0;

  shortopt[0] = '-';
  min_len = 0;
  max_len = ~0;

#define getarg()                                \
  do {                                          \
    if ('-' == arg[1] || !arg[2]) {             \
      i++;                                      \
      if (i == argc) {                          \
        die("missing argument: %s\n", opt);     \
      } else {                                  \
        arg = argv[i];                          \
      }                                         \
    } else {                                    \
      arg = &arg[2];                            \
    }                                           \
  } while (0)

#define getcls()                                    \
  do {                                              \
    for (j = 0;; j++) {                             \
      if (!classes[j].name) {                       \
        cls = NULL;                                 \
        break;                                      \
      }                                             \
      if (0 == strcmp(cls, classes[j].name)) {      \
        cls = classes[j].class;                     \
        break;                                      \
      }                                             \
    }                                               \
  } while (0)

#define badarg()                                    \
  do {                                              \
    die("invalid argument to %s: %s\n", opt, arg);  \
  } while (0)

  for (i = 1; i < argc; i++) {
    arg = argv[i];
    if ('-' == arg[0]) {
      if ('-' == arg[1]) {
        opt = arg;

        if (0 == strcmp(opt, "--char")) {
        opt_char:
          getarg();

          if (1 == strlen(arg)) {
            charset_union(opts.add_chars, arg);
          } else {
            n = s2uint(arg);
            if (n == 0 || n > 0xff) {
              die("invalid byte value: %s\n", arg);
            }
            cbuf[0] = (char)n;
            charset_union(opts.add_chars, cbuf);
          }

        } else if (0 == strcmp(opt, "--prefix")) {
        opt_prefix:
          getarg();
          opts.prefix = arg;

        } else if (0 == strcmp(opt, "--suffix")) {
        opt_suffix:
          getarg();
          opts.suffix = arg;

        } else if (0 == strcmp(opt, "--binary")) {
        opt_binary:
          opts.is_binary = true;

        } else if (0 == strcmp(opt, "--endian")) {
        opt_endian:
          getarg();
          if (strcmp(arg, "b") &&
              strcmp(arg, "big") &&
              strcmp(arg, "l") &&
              strcmp(arg, "little")) {
            badarg();
          }
          opts.big_endian = 'b' == arg[0];

        } else if (0 == strcmp(opt, "--length")) {
        opt_length:
          getarg();
          min_len = s2uint(arg);
          max_len = min_len;

        } else if (0 == strcmp(opt, "--min-length")) {
          getarg();
          max_len = s2uint(arg);

        } else if (0 == strcmp(opt, "--max-length")) {
          getarg();
          min_len = s2uint(arg);

        } else if (0 == strcmp(opt, "--ccc")) {
        opt_ccc:
          opts.is_ccc = true;
          opts.algo = &algo_sha256;

        } else if (0 == strcmp(opt, "--threads")) {
        opt_threads:
          getarg();
          opts.num_threads = s2uint(arg);

        } else if (0 == strcmp(opt, "--max-tries")) {
          getarg();
          opts.max_tries = (unsigned long long)s2uint(arg) * 1000000;

        } else if (0 == strcmp(opt, "--timeout")) {
        opt_timeout:
          getarg();
          opts.timeout = s2uint(arg);

        } else if (0 == strcmp(opt, "--verbose")) {
        opt_verbose:
          opts.verbose = true;

        } else if (0 == strcmp(opt, "--help")) {
        opt_help:
          usage(argv[0]);

        } else if (0 == memcmp(opt, "--no-", 5)) {
          cls = &opt[5];
          getcls();
          if (!cls) {
            arg = &opt[5];
            if (1 == strlen(arg)) {
              charset_union(opts.rem_chars, arg);
            } else {
              n = s2uint(arg);
              if (n == 0 || n > 0xff) {
                die("no such character class or invalid byte value: %s", opt);
              }
              cbuf[0] = (char)n;
              cls = cbuf;
            }
          }
          charset_union(opts.rem_chars, cls);

        } else {
          cls = &opt[2];
          getcls();
          if (!cls) {
          opt_unknown:
            die("unknown option: %s\n", opt);
          }
          charset_union(opts.add_chars, cls);

        }

      } else {
        shortopt[1] = arg[1];
        opt = shortopt;

        if ('1' == opt[1] || '0' == opt[1] || '?' == opt[1]) {
          goto opt_mask;
        } else if ('c' == opt[1]) {
          goto opt_char;
        } else if ('p' == arg[1]) {
          goto opt_prefix;
        } else if ('s' == arg[1]) {
          goto opt_suffix;
        } else if ('b' == arg[1]) {
          goto opt_binary;
        } else if ('e' == arg[1]) {
          goto opt_endian;
        } else if ('n' == arg[1]) {
          goto opt_length;
        } else if ('J' == arg[1]) {
          goto opt_threads;
        } else if ('t' == arg[1]) {
          goto opt_timeout;
        } else if ('h' == arg[1]) {
          goto opt_help;
        } else if ('v' == arg[1]) {
          goto opt_verbose;
        } else {
          goto opt_unknown;
        }

      }
    } else if (opts.is_ccc) {
      if (opts.challenge) {
        die("challenge given twice\n");
      }
      opts.hardness = strtoll(arg, &opts.challenge, 10);
      if (!(opts.hardness && opts.challenge && opts.challenge[0] == '_')) {
        die("invalid challenge format (must be <number>_<string>)\n");
      }
      opts.challenge++;
      opts.target = calculate_target(opts.hardness);
    } else {
      if ('1' == arg[0] || '0' == arg[0] || '?' == arg[0]) {
      opt_mask:
        if (opts.mask) {
          die("mask given twice\n");
        }
        opts.mask = arg;
      } else {
        if (opts.algo) {
          die("algorithm given twice\n");
        }
        for (j = 0; algos[j].name; j++) {
          if (0 == strcmp(arg, algos[j].name)) {
            opts.algo = algos[j].algo;
            break;
          }
        }
        if (!opts.algo) {
          die("algorithm not supported: %s\n", arg);
        }
      }
    }
  }

  if (opts.is_ccc) {
    if (!opts.challenge) {
      die("missing argument: challenge\n");
    }
  } else {
    if (!opts.algo) {
      die("missing argument: algorithm\n");
    } else if (!opts.mask) {
      die("missing argument: mask\n");
    }

    if (opts.add_chars[0]) {
      strcpy(opts.alphabet, opts.add_chars);
    } else {
      if (opts.is_binary) {
        for (i = 0; i < 0x100; i++) {
          opts.alphabet[i] = (i + 1) & 0xff;
        }
      } else {
        strcpy(opts.alphabet, DEFAULT_ALPHABET);
      }
    }

    charset_discard(opts.alphabet, opts.rem_chars);

    if (opts.is_binary) {
      if (opts.prefix) {
        opts.prefix = unhex(opts.prefix);
      }
      if (opts.suffix) {
        opts.suffix = unhex(opts.suffix);
      }
    }

    parse_mask();

    fixed_len = strlen(opts.prefix) + strlen(opts.suffix);

    if (min_len > max_len) {
      die("minimal length is larger than maximal length\n");
    }

    if (fixed_len >= max_len) {
      die("length is too short\n");
    }

    /* Number of characters needed to make the search space >= `max_tries` */
    search_len = log((double)opts.max_tries) /
      log((double)strlen(opts.alphabet));

    opts.pow_len = fixed_len + search_len;

    if (opts.pow_len < min_len) {
      opts.pow_len = min_len;
    } else if (opts.pow_len > max_len) {
      opts.pow_len = max_len;
      /* Length restriction takes precedent over `max_tries` */
      search_len = opts.pow_len - fixed_len;
      opts.max_tries = pow((double)strlen(opts.alphabet), (double)search_len);
    }
  }

#undef getarg
#undef getcls
#undef badarg
}
void show_large_num(unsigned long long n);
void *worker_std(void *arg) {
  unsigned long long start;
  size_t i, j, free_len, alen, plen, slen;
  char *pow, *pow_search;
  unsigned char *stack, *digest;
  void *ctx, *ctx_;

  alen = strlen(opts.alphabet);
  plen = strlen(opts.prefix);
  slen = strlen(opts.suffix);

  ctx = malloc(opts.algo->ctx_size);
  ctx_ = malloc(opts.algo->ctx_size);

  digest = malloc(opts.algo->digest_size);

  pow = malloc(opts.pow_len + 1);
  strcpy(pow, opts.prefix);
  strcpy(&pow[opts.pow_len - slen], opts.suffix);
  pow_search = &pow[plen];

  start = (unsigned long long)arg;
  free_len = opts.pow_len - plen - slen;
  stack = malloc(free_len);

  for (i = 0; i < free_len; i++) {
    stack[i] = start % alen;
    start /= alen;
    pow_search[i] = opts.alphabet[stack[i]];
  }

  opts.algo->init(ctx);
  opts.algo->update(ctx, opts.prefix, plen);

  for (i = 0; i < opts.max_tries / opts.num_threads && !g_quit; i++) {

    if (i % 1000000 == 0) {
      pthread_mutex_lock(&g_lock);
      g_progress += 1000000;
      fprintf(stderr, "\033[G\033[K");
      show_large_num(g_progress);
      fflush(stderr);
      pthread_mutex_unlock(&g_lock);
    }

    memcpy(ctx_, ctx, opts.algo->ctx_size);
    opts.algo->update(ctx_, pow_search, opts.pow_len - plen);
    opts.algo->final(digest, ctx_);

    for (j = 0; j < opts.algo->digest_size; j++) {
      if (opts.zmask[j] & digest[j]) {
        break;
      }
      if (opts.omask[j] != (opts.omask[j] & digest[j])) {
        break;
      }
    }
    if (j == opts.algo->digest_size) {
      g_quit = true;
      pthread_mutex_lock(&g_lock);
      if (!g_pow) {
        g_pow = pow;
      }
      pthread_mutex_unlock(&g_lock);
      return (void*)i;
    }

    for (j = 0;; j++) {
      if (++stack[j] == alen) {
        stack[j] = 0;
        pow_search[j] = opts.alphabet[0];
      } else {
        pow_search[j] = opts.alphabet[stack[j]];
        break;
      }
    }
  }

  return (void*)i;
}

void *worker_ccc(void *arg) {
  uint64_t pow;
  size_t i;
  bn_t digest;
  void *ctx, *ctx_;

  ctx = malloc(opts.algo->ctx_size);
  ctx_ = malloc(opts.algo->ctx_size);

  digest = malloc(opts.algo->digest_size);

  pow = (uint64_t)arg;

  opts.algo->init(ctx);
  opts.algo->update(ctx, opts.challenge, strlen(opts.challenge));

  for (i = 0; i < opts.max_tries / opts.num_threads && !g_quit; i++, pow++) {
    memcpy(ctx_, ctx, opts.algo->ctx_size);
    opts.algo->update(ctx_, &pow, sizeof(pow));
    opts.algo->final(digest, ctx_);

    if (bn_cmp(digest, opts.target) < 0) {
      g_quit = true;
      pthread_mutex_lock(&g_lock);
      if (!g_pow) {
        opts.pow_len = asprintf(&g_pow, "%lu", pow);
      }
      pthread_mutex_unlock(&g_lock);
      return (void*)i;
    }
  }

  return (void*)i;
}

void show_bignum(bn_t a) {
  int i;
  for (i = 0; i < bn_size; i++) {
    if (a[i]) {
      break;
    }
  }
  fprintf(stderr, "0x%x", a[i]);
  for (i++; i < bn_size; i++) {
    fprintf(stderr, "%02x", a[i]);
  }
}

void show_large_num(unsigned long long n) {
  size_t i;
  const char* units[] = {"", "K", "M", "G", "T"};

  i = 0;
  while (n >= 1000 && i <= sizeof(units)/sizeof(units[0])) {
    /* Round to nearest */
    n = (n + 500) / 1000;
    i++;
  }
  fprintf(stderr, "%llu%s", n, units[i]);
}

void show_string(unsigned char *str, size_t columns, size_t indentation) {
  unsigned char c;
  size_t col;

  col = indentation;

#define wrap(n)                                         \
  do {                                                  \
    col += n;                                           \
    if (col >= columns) {                               \
      col = indentation + n;                            \
      fprintf(stderr, "\n%*s", (int)indentation, "");   \
    }                                                   \
  } while (0)

  while ((c = *str++)) {
    switch (c) {

    case '\\':
      wrap(2);
      fprintf(stderr, "\\\\");
      break;

    case '\n':
      wrap(2);
      fprintf(stderr, "\\n");
      break;

    case '\r':
      wrap(2);
      fprintf(stderr, "\\r");
      break;

    default:
      if (c > ' ' && c <= '~') {
        wrap(1);
        fprintf(stderr, "%c", c);
      } else {
        wrap(4);
        fprintf(stderr, "\\x%02x", c);
      }
    }
  }
}

void sighandler(int signum) {
  g_quit = true;
}

int main(int argc, char *argv[]) {
  size_t i;
  pthread_t *threads;
  unsigned long long start, *tries, tries_total;
  struct sigaction sa;
  struct timeval now, then, elapsed;

  parse_args(argc, argv);

  if (opts.verbose) {
    if (opts.is_ccc) {
      fprintf(stderr, "Algorithm: CCC(%s)\n", opts.algo->name);
      fprintf(stderr, "Challenge: %s\n", opts.challenge);
      fprintf(stderr, "Hardness : %llu\n", opts.hardness);
      fprintf(stderr, "Target   : ");
      show_bignum(opts.target);
      fprintf(stderr, "\n");
    } else {
      fprintf(stderr, "Algorithm: %s\n", opts.algo->name);
      fprintf(stderr, "Alphabet : ");
      show_string(opts.alphabet, 80, 11);
      fprintf(stderr, "\n");
      fprintf(stderr, "           (%lu characters)\n", strlen(opts.alphabet));
      fprintf(stderr, "Prefix   : ");
      show_string(opts.prefix, 80, 11);
      fprintf(stderr, "\n");
      fprintf(stderr, "Suffix   : ");
      show_string(opts.suffix, 80, 11);
      fprintf(stderr, "\n");
      fprintf(stderr, "Mask     :");
      for (i = 0; i < opts.algo->digest_size * 8; i++) {
        if (i % 8 == 0) {
          fprintf(stderr, " ");
        }
        if (i && i % 64 == 0) {
          fprintf(stderr, "\n           ");
        }
        if (opts.omask[i / 8] & (1 << (7 - i % 8))) {
          fprintf(stderr, "1");
        } else if (opts.zmask[i / 8] & (1 << (7 - i % 8))) {
          fprintf(stderr, "0");
        } else {
          fprintf(stderr, "?");
        }
      }
      fprintf(stderr, "\n");
      fprintf(stderr, "Length   : %lu\n", opts.pow_len);
      fprintf(stderr, "Endian   : %s\n", opts.big_endian ? "big" : "little");
      fprintf(stderr, "Binary   : %s\n", opts.is_binary ? "yes" : "no");
    }
    fprintf(stderr, "Threads  : %lu\n", opts.num_threads);
    fprintf(stderr, "Max tries: ");
    show_large_num(opts.max_tries);
    fprintf(stderr, " (");
    show_large_num(opts.max_tries / opts.num_threads);
    fprintf(stderr, " per thread)\n");
    fprintf(stderr, "Timeout  : ");
    if (opts.timeout) {
      fprintf(stderr, "%lus\n", opts.timeout);
    } else {
      fprintf(stderr, "none\n");
    }
  }

  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = sighandler;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGALRM, &sa, NULL);

  if (opts.timeout) {
    alarm(opts.timeout);
  }

  gettimeofday(&then, NULL);

  threads = calloc(opts.num_threads, sizeof(threads[0]));
  tries = calloc(opts.num_threads, sizeof(tries[0]));

  for (i = 0; i < opts.num_threads; i++) {
    start = (opts.max_tries * i) / opts.num_threads;
    pthread_create(&threads[i], NULL, opts.is_ccc ? worker_ccc : worker_std,
                   (void*)start);
  }

  tries_total = 0;
  for (i = 0; i < opts.num_threads; i++) {
    pthread_join(threads[i], (void*)&tries[i]);

    if (0 == i && opts.verbose) {
      fprintf(stderr, "\nDigests calculated:\n");
    }

    tries_total += tries[i];
    if (opts.verbose) {
      fprintf(stderr, "Thread %-2lu: ", i);
      show_large_num(tries[i]);
      fprintf(stderr, "\n");
    }
  }

  gettimeofday(&now, NULL);
  timersub(&now, &then, &elapsed);

  if (opts.verbose) {
    fprintf(stderr, "In total : ");
    show_large_num(tries_total);
    fprintf(stderr, "\n");
    fprintf(stderr, "Speed    : ");
    show_large_num((1000000 * tries_total) /
                   (elapsed.tv_usec + 1000000 * elapsed.tv_sec));
    fprintf(stderr, "/s\n\n");
  }

  if (g_pow) {
    write(STDOUT_FILENO, g_pow, opts.pow_len);
    if (isatty(STDOUT_FILENO)) {
      printf("\n");
    }
    return EXIT_SUCCESS;
  } else {
    if (opts.verbose) {
      fprintf(stderr, "No solution\n");
    }
    return EXIT_FAILURE;
  }
}
