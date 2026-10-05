/*
 * mzchecksum - DOS EXE checksum tool
 * SPDX-License-Identifier: MIT-0
 * Copyright (c) 2026 Jeffrey H. Johnson <johnsonjh.dev@gmail.com>
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(UCHAR_MAX)
# if UCHAR_MAX != 255U
#  error "8-bit bytes required"
# endif
#endif

#define EXIT_OK_CODE 0
#define EXIT_MISMATCH_CODE 1
#define EXIT_ERROR_CODE 2

#define DOS_HEADER_MIN 28UL
#define DOS_EXT_HEADER_MIN 64UL
#define CHECKSUM_OFFSET 18UL
#define NEW_HEADER_OFFSET 60UL
#define CHECKSUM_BUFFER_SIZE 4096U

#define SCOPE_LOGICAL 0
#define SCOPE_PHYSICAL 1

#define MODE_GET 0
#define MODE_SET 1

struct options
{
  int mode;
  int scope;
  int set_auto;
  int target_seen;
  unsigned int set_value;
  unsigned int target;
  const char *filename;
};

struct mz_info
{
  char signature[3];
  unsigned int checksum;
  unsigned long logical_size;
  unsigned long physical_size;
  unsigned long header_size;
  unsigned int relocation_count;
  unsigned int relocation_offset;
  int is_ne;
};

static void
print_usage (const char *prog)
{
  (void)fprintf (stderr, "Usage: %s [options] file\n\n", prog);

  (void)fputs ("Major modes (mutually exclusive):\n", stderr);
  (void)fputs ("  -g, --get              Display and verify the DOS EXE "
               "checksum (default)\n",
               stderr);
  (void)fputs ("  -s, --set VALUE        Set checksum to four hex digits or "
               "to 'auto'\n\n",
               stderr);
  (void)fputs ("Checksum scope (mutually exclusive):\n", stderr);
  (void)fputs ("  -l, --logical          Exclude bytes beyond the MZ logical "
               "size (default)\n",
               stderr);
  (void)fputs ("  -p, --physical         Include all physical file bytes\n\n",
               stderr);
  (void)fputs ("Verification target:\n", stderr);
  (void)fputs ("  -t, --target HEX       Required checksum sum; exactly four "
               "hex digits\n",
               stderr);
  (void)fputs (
      "                         with optional 0x/0X prefix (default FFFF)\n\n",
      stderr);
  (void)fputs ("Other:\n", stderr);
  (void)fputs ("  -h, --help             Show this help\n\n", stderr);

  (void)fputs ("Examples:\n", stderr);
  (void)fprintf (stderr, "  %s program.exe\n", prog);
  (void)fprintf (stderr, "  %s --physical --target FFFF program.exe\n", prog);
  (void)fprintf (stderr, "  %s --set auto program.exe\n", prog);
  (void)fprintf (stderr, "  %s --set 1234 --target FFFF program.exe\n", prog);
}

static int
hex_value (int c)
{
  if (c >= '0' && c <= '9')
    {
      return c - '0';
    }

  if (c >= 'a' && c <= 'f')
    {
      return c - 'a' + 10;
    }

  if (c >= 'A' && c <= 'F')
    {
      return c - 'A' + 10;
    }

  return -1;
}

static int
parse_hex16 (const char *s, unsigned int *value)
{
  const char *p;
  unsigned long v;
  int i;

  if (s == NULL || value == NULL)
    {
      return 0;
    }

  p = s;

  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
    {
      p += 2;
    }

  if (strlen (p) != 4U)
    {
      return 0;
    }

  v = 0UL;
  for (i = 0; i < 4; ++i)
    {
      int d = hex_value ((unsigned char)p[i]);

      if (d < 0)
        {
          return 0;
        }

      v = (v << 4) | (unsigned long)d;
    }

  *value = (unsigned int)v;

  return 1;
}

static int
is_auto_value (const char *s)
{
  if (s == NULL)
    {
      return 0;
    }

  return (s[0] == 'a' || s[0] == 'A') && (s[1] == 'u' || s[1] == 'U')
         && (s[2] == 't' || s[2] == 'T') && (s[3] == 'o' || s[3] == 'O')
         && s[4] == '\0';
}

static int
option_error (const char *prog, const char *message)
{
  (void)fprintf (stderr, "%s: error: %s\n", prog, message);
  (void)fprintf (stderr, "Try '%s --help' for usage.\n", prog);

  return EXIT_ERROR_CODE;
}

static int
option_error_arg (const char *prog, const char *message, const char *arg)
{
  (void)fprintf (stderr, "%s: error: %s: %s\n", prog, message, arg);
  (void)fprintf (stderr, "Try '%s --help' for usage.\n", prog);

  return EXIT_ERROR_CODE;
}

static int
parse_options (int argc, char **argv, const char *prog, struct options *opt,
               int *help_requested)
{
  int i;
  int end_options;
  int physical_seen;
  int logical_seen;
  int target_seen;
  int set_seen;
  int get_seen;
  int help_seen;
  const char *arg;

  opt->mode = MODE_GET;
  opt->scope = SCOPE_LOGICAL;
  opt->set_auto = 0;
  opt->target_seen = 0;
  opt->set_value = 0U;
  opt->target = 0xffffU;
  opt->filename = NULL;
  *help_requested = 0;

  end_options = 0;
  physical_seen = 0;
  logical_seen = 0;
  target_seen = 0;
  set_seen = 0;
  get_seen = 0;
  help_seen = 0;

  i = 1;
  while (i < argc)
    {
      arg = argv[i];

      if (!end_options && strcmp (arg, "--") == 0)
        {
          end_options = 1;
          ++i;

          continue;
        }

      if (!end_options && arg[0] == '-' && arg[1] == '-' && arg[2] != '\0')
        {
          const char *value_arg;

          if (strcmp (arg, "--physical") == 0)
            {
              if (physical_seen)
                {
                  return option_error (prog,
                                       "--physical specified more than once");
                }

              if (logical_seen)
                {
                  return option_error (prog,
                      "--physical and --logical are mutually exclusive");
                }

              physical_seen = 1;
              opt->scope = SCOPE_PHYSICAL;
            }
          else if (strcmp (arg, "--logical") == 0)
            {
              if (logical_seen)
                {
                  return option_error (prog,
                                       "--logical specified more than once");
                }

              if (physical_seen)
                {
                  return option_error (prog,
                      "--logical and --physical are mutually exclusive");
                }

              logical_seen = 1;
              opt->scope = SCOPE_LOGICAL;
            }
          else if (strcmp (arg, "--get") == 0)
            {
              if (get_seen)
                {
                  return option_error (prog, "--get specified more than once");
                }

              if (set_seen)
                {
                  return option_error (
                      prog, "--get and --set are mutually exclusive");
                }

              get_seen = 1;
              opt->mode = MODE_GET;
            }
          else if (strcmp (arg, "--help") == 0)
            {
              if (help_seen)
                {
                  return option_error (prog,
                                       "--help specified more than once");
                }

              help_seen = 1;
              *help_requested = 1;
            }
          else if (strncmp (arg, "--target=", 9U) == 0)
            {
              if (target_seen)
                {
                  return option_error (prog,
                                       "--target specified more than once");
                }

              value_arg = arg + 9;

              if (!parse_hex16 (value_arg, &opt->target))
                {
                  return option_error_arg (prog, "invalid --target value",
                                           value_arg);
                }

              target_seen = 1;
              opt->target_seen = 1;
            }
          else if (strcmp (arg, "--target") == 0)
            {
              if (target_seen)
                {
                  return option_error (prog,
                                       "--target specified more than once");
                }

              if (i + 1 >= argc)
                {
                  return option_error (prog, "--target requires an argument");
                }

              ++i;
              value_arg = argv[i];

              if (!parse_hex16 (value_arg, &opt->target))
                {
                  return option_error_arg (prog, "invalid --target value",
                                           value_arg);
                }

              target_seen = 1;
              opt->target_seen = 1;
            }
          else if (strncmp (arg, "--set=", 6U) == 0)
            {
              if (set_seen)
                {
                  return option_error (prog, "--set specified more than once");
                }

              if (get_seen)
                {
                  return option_error (
                      prog, "--set and --get are mutually exclusive");
                }

              value_arg = arg + 6;
              if (is_auto_value (value_arg))
                {
                  opt->set_auto = 1;
                }
              else if (!parse_hex16 (value_arg, &opt->set_value))
                {
                  return option_error_arg (prog, "invalid --set value",
                                           value_arg);
                }

              set_seen = 1;
              opt->mode = MODE_SET;
            }
          else if (strcmp (arg, "--set") == 0)
            {
              if (set_seen)
                {
                  return option_error (prog, "--set specified more than once");
                }

              if (get_seen)
                {
                  return option_error (
                      prog, "--set and --get are mutually exclusive");
                }

              if (i + 1 >= argc)
                {
                  return option_error (prog, "--set requires an argument");
                }

              ++i;
              value_arg = argv[i];

              if (is_auto_value (value_arg))
                {
                  opt->set_auto = 1;
                }
              else if (!parse_hex16 (value_arg, &opt->set_value))
                {
                  return option_error_arg (prog, "invalid --set value",
                                           value_arg);
                }

              set_seen = 1;
              opt->mode = MODE_SET;
            }
          else
            {
              return option_error_arg (prog, "unknown option", arg);
            }
        }
      else if (!end_options && arg[0] == '-' && arg[1] != '\0')
        {
          const char *p;

          p = arg + 1;

          while (*p != '\0')
            {
              char c;

              c = *p++;

              if (c == 'p')
                {
                  if (physical_seen)
                    {
                      return option_error (prog,
                          "-p/--physical specified more than once");
                    }

                  if (logical_seen)
                    {
                      return option_error (prog,
                          "-p/--physical and -l/--logical are "
                          "mutually exclusive");
                    }

                  physical_seen = 1;
                  opt->scope = SCOPE_PHYSICAL;
                }
              else if (c == 'l')
                {
                  if (logical_seen)
                    {
                      return option_error (prog,
                          "-l/--logical specified more than once");
                    }

                  if (physical_seen)
                    {
                      return option_error (prog,
                          "-l/--logical and -p/--physical are "
                          "mutually exclusive");
                    }

                  logical_seen = 1;
                  opt->scope = SCOPE_LOGICAL;
                }
              else if (c == 'g')
                {
                  if (get_seen)
                    {
                      return option_error (prog,
                          "-g/--get specified more than once");
                    }

                  if (set_seen)
                    {
                      return option_error (prog,
                          "-g/--get and -s/--set are mutually exclusive");
                    }

                  get_seen = 1;
                  opt->mode = MODE_GET;
                }
              else if (c == 'h')
                {
                  if (help_seen)
                    {
                      return option_error (prog,
                          "-h/--help specified more than once");
                    }

                  help_seen = 1;
                  *help_requested = 1;
                }
              else if (c == 't' || c == 's')
                {
                  const char *value_arg;

                  if (*p != '\0')
                    {
                      value_arg = p;
                    }
                  else
                    {
                      if (i + 1 >= argc)
                        {
                          if (c == 't')
                            {
                              return option_error (prog,
                                  "-t/--target requires an argument");
                            }

                          return option_error (prog,
                              "-s/--set requires an argument");
                        }

                      ++i;
                      value_arg = argv[i];
                    }

                  if (c == 't')
                    {
                      if (target_seen)
                        {
                          return option_error (prog,
                              "-t/--target specified more than once");
                        }

                      if (!parse_hex16 (value_arg, &opt->target))
                        {
                          return option_error_arg (prog,
                              "invalid -t/--target value", value_arg);
                        }

                      target_seen = 1;
                      opt->target_seen = 1;
                    }
                  else
                    {
                      if (set_seen)
                        {
                          return option_error (prog,
                              "-s/--set specified more than once");
                        }

                      if (get_seen)
                        {
                          return option_error (prog,
                              "-s/--set and -g/--get are mutually exclusive");
                        }

                      if (is_auto_value (value_arg))
                        {
                          opt->set_auto = 1;
                        }
                      else if (!parse_hex16 (value_arg, &opt->set_value))
                        {
                          return option_error_arg (prog,
                              "invalid -s/--set value", value_arg);
                        }

                      set_seen = 1;
                      opt->mode = MODE_SET;
                    }

                  break;
                }
              else
                {
                  char bad[3];
                  bad[0] = '-';
                  bad[1] = c;
                  bad[2] = '\0';

                  return option_error_arg (prog, "unknown option", bad);
                }
            }
        }
      else
        {
          if (opt->filename != NULL)
            {
              return option_error (prog, "more than one input file specified");
            }

          opt->filename = arg;
        }

      ++i;
    }

  if (*help_requested)
    {
      return EXIT_OK_CODE;
    }

  if (opt->filename == NULL)
    {
      return option_error (prog, "no input file specified");
    }

  return EXIT_OK_CODE;
}

static unsigned int
get_u16le (const unsigned char *p)
{
  unsigned long v;

  v = (unsigned long)p[0] | ((unsigned long)p[1] << 8);

  return (unsigned int)v;
}

static unsigned long
get_u32le (const unsigned char *p)
{
  unsigned long v;

  v = (unsigned long)p[0];
  v |= (unsigned long)p[1] << 8;
  v |= (unsigned long)p[2] << 16;
  v |= (unsigned long)p[3] << 24;

  return v;
}

static int
get_physical_size (FILE *fp, unsigned long *size)
{
  long pos;

  if (fseek (fp, 0L, SEEK_END) != 0)
    {
      return 0;
    }

  pos = ftell (fp);

  if (pos < 0L)
    {
      return 0;
    }

  *size = (unsigned long)pos;

  return 1;
}

static int
inspect_mz (FILE *fp, const char *filename, struct mz_info *info)
{
  unsigned char header[64];
  size_t need;
  size_t got;
  unsigned int cblp;
  unsigned int cp;
  unsigned int cparhdr;

  if (!get_physical_size (fp, &info->physical_size))
    {
      (void)fprintf (stderr, "%s: error: cannot determine file size\n",
                     filename);

      return 0;
    }

  if (info->physical_size < DOS_HEADER_MIN)
    {
      (void)fprintf (stderr,
                     "%s: error: file is too small for a DOS MZ header\n",
                     filename);

      return 0;
    }

  (void)memset (header, 0, sizeof (header));
  need = sizeof (header);
  if (info->physical_size < (unsigned long)need)
    {
      need = (size_t)info->physical_size;
    }

  if (fseek (fp, 0L, SEEK_SET) != 0)
    {
      (void)fprintf (stderr, "%s: error: cannot seek to DOS header\n",
                     filename);

      return 0;
    }

  got = fread (header, 1U, need, fp);
  if (got != need)
    {
      (void)fprintf (stderr, "%s: error: cannot read DOS header\n", filename);

      return 0;
    }

  if (!((header[0] == 'M' && header[1] == 'Z')
        || (header[0] == 'Z' && header[1] == 'M')))
    {
      (void)fprintf (stderr, "%s: error: not an MZ/ZM executable\n", filename);

      return 0;
    }

  info->signature[0] = (char)header[0];
  info->signature[1] = (char)header[1];
  info->signature[2] = '\0';

  cblp = get_u16le (header + 2);
  cp = get_u16le (header + 4);
  info->relocation_count = get_u16le (header + 6);
  cparhdr = get_u16le (header + 8);
  info->checksum = get_u16le (header + CHECKSUM_OFFSET);
  info->relocation_offset = get_u16le (header + 24);

  if (cblp > 511U)
    {
      (void)fprintf (stderr,
          "%s: error: invalid MZ header: bytes-in-last-page value is %u\n",
          filename, cblp);

      return 0;
    }

  if (cp == 0U)
    {
      (void)fprintf (stderr,
                     "%s: error: invalid MZ header: page count is zero\n",
                     filename);

      return 0;
    }

  if (cblp == 0U)
    {
      info->logical_size = (unsigned long)cp * 512UL;
    }
  else
    {
      info->logical_size
          = ((unsigned long)cp - 1UL) * 512UL + (unsigned long)cblp;
    }

  info->header_size = (unsigned long)cparhdr * 16UL;

  if (info->header_size < DOS_HEADER_MIN)
    {
      (void)fprintf (stderr,
          "%s: error: invalid MZ header: declared header is only %lu bytes\n",
          filename, info->header_size);

      return 0;
    }

  if (info->header_size > info->logical_size)
    {
      (void)fprintf (stderr,
                     "%s: error: invalid MZ header: declared header exceeds "
                     "logical file size\n",
                     filename);

      return 0;
    }

  if (info->logical_size > info->physical_size)
    {
      (void)fprintf (stderr,
                     "%s: error: truncated MZ executable: logical size is %lu "
                     "bytes, physical size is %lu bytes\n",
                     filename, info->logical_size, info->physical_size);

      return 0;
    }

  if (info->relocation_count != 0U)
    {
      unsigned long relocation_end
          = (unsigned long)info->relocation_offset
            + (unsigned long)info->relocation_count * 4UL;
      if ((unsigned long)info->relocation_offset < DOS_HEADER_MIN
          || (unsigned long)info->relocation_offset >= info->header_size
          || relocation_end > info->header_size)
        {
          (void)fprintf (stderr,
                         "%s: error: invalid MZ header: relocation table is "
                         "outside the usable declared header area\n",
                         filename);

          return 0;
        }
    }

  info->is_ne = 0;

  if (info->header_size >= DOS_EXT_HEADER_MIN
      && info->physical_size >= DOS_EXT_HEADER_MIN)
    {
      unsigned long new_header = get_u32le (header + NEW_HEADER_OFFSET);

      if (new_header <= info->physical_size - 2UL)
        {
          unsigned char sig[2];

          if (fseek (fp, (long)new_header, SEEK_SET) != 0)
            {
              (void)fprintf (stderr,
                  "%s: error: cannot seek to possible new executable header\n",
                  filename);
              return 0;
            }

          if (fread (sig, 1U, 2U, fp) != 2U)
            {
              (void)fprintf (stderr,
                  "%s: error: cannot read possible new executable header\n",
                  filename);

              return 0;
            }

          if (sig[0] == 'N' && sig[1] == 'E')
            {
              info->is_ne = 1;
            }
        }
    }

  return 1;
}

static int
checksum_sum (FILE *fp, unsigned long byte_count, int zero_checksum_field,
              unsigned int *result)
{
  unsigned char buffer[CHECKSUM_BUFFER_SIZE];
  unsigned long remaining;
  unsigned long position;
  unsigned long sum;
  unsigned int low_byte;
  int have_low_byte;

  if (fseek (fp, 0L, SEEK_SET) != 0)
    {
      return 0;
    }

  remaining = byte_count;
  position = 0UL;
  sum = 0UL;
  low_byte = 0U;
  have_low_byte = 0;

  while (remaining != 0UL)
    {
      size_t want;
      size_t got;
      size_t i;

      if (remaining > (unsigned long)sizeof (buffer))
        {
          want = sizeof (buffer);
        }
      else
        {
          want = (size_t)remaining;
        }

      got = fread (buffer, 1U, want, fp);

      if (got != want)
        {
          return 0;
        }

      for (i = 0U; i < got; ++i, ++position)
        {
          unsigned int b;

          b = (unsigned int)buffer[i];

          if (zero_checksum_field
              && (position == CHECKSUM_OFFSET
                  || position == CHECKSUM_OFFSET + 1UL))
            {
              b = 0U;
            }

          if (!have_low_byte)
            {
              low_byte = b;
              have_low_byte = 1;
            }
          else
            {
              sum += (unsigned long)low_byte + ((unsigned long)b << 8);
              sum &= 0xffffUL;
              have_low_byte = 0;
            }
        }

      remaining -= (unsigned long)got;
    }

  if (have_low_byte)
    {
      sum += (unsigned long)low_byte;
      sum &= 0xffffUL;
    }

  *result = (unsigned int)sum;

  return 1;
}

static int
write_checksum (FILE *fp, unsigned int value)
{
  unsigned char b[2];

  b[0] = (unsigned char)(value & 0xffU);
  b[1] = (unsigned char)((value >> 8) & 0xffU);

  if (fseek (fp, (long)CHECKSUM_OFFSET, SEEK_SET) != 0)
    {
      return 0;
    }

  if (fwrite (b, 1U, 2U, fp) != 2U)
    {
      return 0;
    }

  if (fflush (fp) != 0)
    {
      return 0;
    }

  return 1;
}

static void
print_file_info (const struct mz_info *info)
{
  (void)printf ("Signature: %s\n", info->signature);
  (void)printf ("Logical size: %lu bytes\n", info->logical_size);
  (void)printf ("Physical size: %lu bytes\n", info->physical_size);
  (void)printf ("Overlay size: %lu bytes\n",
                info->physical_size - info->logical_size);
}

static void
print_verification (unsigned int field_value, int scope,
                    unsigned long byte_count, unsigned int target,
                    unsigned int sum)
{
  (void)printf ("Checksum field: 0x%04lX\n", (unsigned long)field_value);
  (void)printf ("Checksum scope: %s (%lu bytes)\n",
                scope == SCOPE_PHYSICAL ? "physical" : "logical", byte_count);
  (void)printf ("Target sum: 0x%04lX\n", (unsigned long)target);
  (void)printf ("Computed sum: 0x%04lX\n", (unsigned long)sum);
  (void)printf ("Verification: %s\n", sum == target ? "OK" : "MISMATCH");
}

int
main (int argc, char **argv)
{
  struct options opt;
  struct mz_info info;
  const char *prog;
  FILE *fp;
  int help_requested;
  int parse_status;
  unsigned long check_size;
  unsigned int sum = 0U;
  unsigned int new_value;
  unsigned int old_value;
  int verify_after_set;

  if (argc > 0 && argv[0] != NULL && argv[0][0] != '\0')
    {
      prog = argv[0];
    }
  else
    {
      prog = "mzchecksum";
    }

  parse_status = parse_options (argc, argv, prog, &opt, &help_requested);
  if (parse_status != EXIT_OK_CODE)
    {
      return parse_status;
    }

  if (help_requested)
    {
      print_usage (prog);

      return EXIT_OK_CODE;
    }

  fp = fopen (opt.filename, opt.mode == MODE_SET ? "r+b" : "rb");
  if (fp == NULL)
    {
      (void)fprintf (stderr, "%s: error: cannot open %s%s\n", prog,
                     opt.filename, opt.mode == MODE_SET ? " for update" : "");

      return EXIT_ERROR_CODE;
    }

  if (!inspect_mz (fp, opt.filename, &info))
    {
      (void)fclose (fp);

      return EXIT_ERROR_CODE;
    }

  if (info.is_ne)
    {
      (void)fprintf (stderr,
                     "%s: warning: NE executable detected; the NE 32-bit "
                     "checksum is not handled\n", prog);
    }

  print_file_info (&info);

  check_size
      = opt.scope == SCOPE_PHYSICAL ? info.physical_size : info.logical_size;
  old_value = info.checksum;

  if (opt.mode == MODE_GET)
    {
      if (!checksum_sum (fp, check_size, 0, &sum))
        {
          (void)fprintf (stderr, "%s: error: failed while reading %s\n", prog,
                         opt.filename);
          (void)fclose (fp);

          return EXIT_ERROR_CODE;
        }

      print_verification (old_value, opt.scope, check_size, opt.target, sum);
      if (fclose (fp) != 0)
        {
          (void)fprintf (stderr, "%s: error: failed to close %s\n", prog,
                         opt.filename);

          return EXIT_ERROR_CODE;
        }

      return sum == opt.target ? EXIT_OK_CODE : EXIT_MISMATCH_CODE;
    }

  if (opt.set_auto)
    {
      unsigned int sum_without_field;

      if (!checksum_sum (fp, check_size, 1, &sum_without_field))
        {
          (void)fprintf (stderr, "%s: error: failed while reading %s\n", prog,
                         opt.filename);
          (void)fclose (fp);

          return EXIT_ERROR_CODE;
        }

      new_value = (unsigned int)(((unsigned long)opt.target + 0x10000UL
                                  - (unsigned long)sum_without_field)
                                 & 0xffffUL);
      verify_after_set = 1;
    }
  else
    {
      new_value = opt.set_value;
      verify_after_set = opt.target_seen;
    }

  if (new_value != old_value)
    {
      if (!write_checksum (fp, new_value))
        {
          (void)fprintf (stderr, "%s: error: failed to write checksum to %s\n",
                         prog, opt.filename);
          (void)fclose (fp);

          return EXIT_ERROR_CODE;
        }
    }

  (void)printf ("Checksum field: 0x%04lX -> 0x%04lX%s\n",
                (unsigned long)old_value, (unsigned long)new_value,
                opt.set_auto ? " (auto)" : "");

  if (verify_after_set)
    {
      if (!checksum_sum (fp, check_size, 0, &sum))
        {
          (void)fprintf (stderr, "%s: error: failed while verifying %s\n",
                         prog, opt.filename);
          (void)fclose (fp);
          return EXIT_ERROR_CODE;
        }

      (void)printf ("Checksum scope: %s (%lu bytes)\n",
                    opt.scope == SCOPE_PHYSICAL ? "physical" : "logical",
                    check_size);
      (void)printf ("Target sum: 0x%04lX\n", (unsigned long)opt.target);
      (void)printf ("Computed sum: 0x%04lX\n", (unsigned long)sum);
      (void)printf ("Verification: %s\n",
                    sum == opt.target ? "OK" : "MISMATCH");

      if (sum != opt.target && !opt.set_auto)
        {
          (void)fprintf (stderr,
                         "%s: warning: explicit checksum 0x%04lX does not "
                         "produce target 0x%04lX (sum is 0x%04lX)\n",
                         prog, (unsigned long)new_value,
                         (unsigned long)opt.target, (unsigned long)sum);
        }
    }
  else
    {
      (void)printf ("Verification: not requested (no --target specified)\n");
    }

  if (fclose (fp) != 0)
    {
      (void)fprintf (stderr, "%s: error: failed to close %s\n", prog,
                     opt.filename);
      return EXIT_ERROR_CODE;
    }

  if (verify_after_set && sum != opt.target)
    {
      return EXIT_MISMATCH_CODE;
    }

  return EXIT_OK_CODE;
}
