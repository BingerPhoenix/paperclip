/* Darwin metadata-only snapshot; no arguments, environments or process memory.
 * SDK: libproc.h, sys/proc_info.h, sys/proc.h, sys/sysctl.h. Build with clang -std=c11
 * -Wall -Wextra -Werror -O2 qualification-process-snapshot.c -o SNAPSHOT.
 * Output start intentionally matches ps lstart (24 local-time C-locale chars).
 * Microseconds are checked internally across reads, but are not exported: PID
 * reuse within the same second across snapshots remains a documented limitation.
 * No source/process arguments or environment content is read by this helper.
 */
#include <errno.h>
#include <libproc.h>
#include <limits.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <time.h>

#define MAX_PROCESSES 8192
#define MAX_OUTPUT (8 * 1024 * 1024)
static char output[MAX_OUTPUT];
static size_t used;
static unsigned int absence_checks;

static int fail(const char *code) {
  fprintf(stderr, "%s\n", code);
  return 1;
}

static int append(const char *text) {
  const size_t length = strlen(text);
  if (length >= sizeof(output) - used) return 0;
  memcpy(output + used, text, length);
  used += length;
  return 1;
}

/* Reject malformed UTF-8 and the unsafe text controls rejected by accounting.
 * An unavailable/unsafe path is null, never a basename or guessed executable. */
static int safe_path(const unsigned char *path) {
  if (path[0] != '/') return 0;
  for (size_t i = 0; path[i];) {
    uint32_t cp = path[i++];
    unsigned int continuation = 0;
    uint32_t minimum = 0;
    if (cp >= 0xc2 && cp <= 0xdf) { continuation = 1; minimum = 0x80; cp &= 0x1f; }
    else if (cp >= 0xe0 && cp <= 0xef) { continuation = 2; minimum = 0x800; cp &= 0x0f; }
    else if (cp >= 0xf0 && cp <= 0xf4) { continuation = 3; minimum = 0x10000; cp &= 0x07; }
    else if (cp >= 0x80) return 0;
    for (unsigned int j = 0; j < continuation; j++) {
      const unsigned char next = path[i++];
      if ((next & 0xc0) != 0x80) return 0;
      cp = (cp << 6) | (next & 0x3f);
    }
    if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ||
        cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) ||
        (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) return 0;
  }
  return 1;
}

static int append_string(const char *text) {
  if (!append("\"")) return 0;
  for (size_t i = 0; text[i]; i++) {
    char one[2] = { text[i], 0 };
    if ((text[i] == '\\' || text[i] == '"') && !append("\\")) return 0;
    if (!append(one)) return 0;
  }
  return append("\"");
}

static const char *state_name(uint32_t status) {
  switch (status) {
    case SIDL: return "I";
    case SRUN: return "R";
    case SSLEEP: return "S";
    case SSTOP: return "T";
    case SZOMB: return "Z";
    default: return "?";
  }
}

/* Darwin can report EPERM when an enumerated process exits during collection.
 * Recheck membership before treating that failure as an exit, never silently
 * omit a still-listed inaccessible identity. Bound these extra list calls. */
static int confirmed_absent(int pid) {
  if (++absence_checks > 16) return 0;
  int current[MAX_PROCESSES + 1];
  const int count = proc_listallpids(current, sizeof(current));
  if (count <= 0 || count > MAX_PROCESSES) return 0;
  for (int i = 0; i < count; i++) if (current[i] == pid) return 0;
  return 1;
}

/* Public basic metadata fallback for host processes whose BSD libproc query is
 * denied. No KERN_PROCARGS/ARGS2, command/title fields or environment is used.
 * Select once per row and use the same provider before and after pidpath. */
static int read_identity(int pid, struct proc_bsdinfo *info, int *provider) {
  memset(info, 0, sizeof(*info));
  if (*provider != 2) {
    errno = 0;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, sizeof(*info)) == sizeof(*info)) {
      *provider = 1;
      return 1;
    }
    if (*provider == 1 || (errno != EPERM && errno != EACCES)) return 0;
    *provider = 2;
  }
  int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  struct kinfo_proc basic;
  memset(&basic, 0, sizeof(basic));
  size_t length = sizeof(basic);
  errno = 0;
  if (sysctl(mib, 4, &basic, &length, NULL, 0) < 0) return 0;
  if (length != sizeof(basic) || basic.kp_proc.p_starttime.tv_sec < 0 ||
      basic.kp_proc.p_starttime.tv_usec < 0 || basic.kp_eproc.e_ppid < 0) {
    errno = EIO;
    return 0;
  }
  info->pbi_pid = (uint32_t)basic.kp_proc.p_pid;
  info->pbi_ppid = (uint32_t)basic.kp_eproc.e_ppid;
  info->pbi_status = (uint32_t)basic.kp_proc.p_stat;
  info->pbi_start_tvsec = (uint64_t)basic.kp_proc.p_starttime.tv_sec;
  info->pbi_start_tvusec = (uint64_t)basic.kp_proc.p_starttime.tv_usec;
  return 1;
}

int main(void) {
  int pids[MAX_PROCESSES + 1];
  memset(pids, 0, sizeof(pids));
  errno = 0;
  const int count = proc_listallpids(pids, sizeof(pids));
  if (count <= 0) return fail("snapshot_list_unavailable");
  if (count > MAX_PROCESSES) return fail("snapshot_process_limit");
  if (!setlocale(LC_TIME, "C")) return fail("snapshot_time_locale");
  if (!append("[")) return fail("snapshot_output_limit");
  int emitted = 0;
  for (int i = 0; i < count; i++) {
    const int pid = pids[i];
    if (pid == 0) continue; /* Kernel PID0 is outside the positive-PID API. */
    if (pid < 0) return fail("snapshot_invalid_pid");
    for (int j = 0; j < i; j++) if (pids[j] == pid) return fail("snapshot_duplicate_pid");
    struct proc_bsdinfo before, after;
    int provider = 0;
    if (!read_identity(pid, &before, &provider)) {
      if (errno == ESRCH || confirmed_absent(pid)) continue;
      return fail("snapshot_identity_unavailable");
    }
    char path[PROC_PIDPATHINFO_MAXSIZE];
    memset(path, 0, sizeof(path));
    const int path_length = proc_pidpath(pid, path, sizeof(path));
    const int path_available = path_length > 0 && path_length < (int)sizeof(path) &&
      memchr(path, 0, sizeof(path)) && safe_path((const unsigned char *)path);
    if (!read_identity(pid, &after, &provider)) {
      if (errno == ESRCH || confirmed_absent(pid)) continue;
      return fail("snapshot_identity_unavailable");
    }
    if (before.pbi_pid != (uint32_t)pid || after.pbi_pid != (uint32_t)pid ||
        before.pbi_start_tvsec != after.pbi_start_tvsec ||
        before.pbi_start_tvusec != after.pbi_start_tvusec) return fail("snapshot_identity_changed");
    if (after.pbi_start_tvsec > INT64_MAX || after.pbi_start_tvusec >= 1000000 ||
        after.pbi_ppid > INT_MAX) return fail("snapshot_invalid_identity");
    const time_t started = (time_t)after.pbi_start_tvsec;
    struct tm local;
    char start[25];
    if (!localtime_r(&started, &local) || strftime(start, sizeof(start), "%a %b %e %H:%M:%S %Y", &local) != 24)
      return fail("snapshot_invalid_start");
    char prefix[96];
    const int written = snprintf(prefix, sizeof(prefix), "%s{\"pid\":%d,\"parent\":%u,\"start\":", emitted ? "," : "", pid, after.pbi_ppid);
    if (written < 0 || written >= (int)sizeof(prefix) || !append(prefix) || !append_string(start) ||
        !append(",\"state\":") || !append_string(state_name(after.pbi_status)) || !append(",\"executable\":"))
      return fail("snapshot_output_limit");
    if (path_available) { if (!append_string(path)) return fail("snapshot_output_limit"); }
    else if (!append("null")) return fail("snapshot_output_limit");
    if (!append("}")) return fail("snapshot_output_limit");
    emitted++;
  }
  if (!emitted) return fail("snapshot_empty");
  if (!append("]\n")) return fail("snapshot_output_limit");
  /* Emit only a complete successful snapshot, never a partial JSON prefix. */
  if (fwrite(output, 1, used, stdout) != used || fflush(stdout)) return fail("snapshot_output_unavailable");
  return 0;
}
