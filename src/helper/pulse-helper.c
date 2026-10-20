/*
 * PULSE/1 Maintenance Helper (pulse-helper)
 *
 * Proprietary maintenance utility for Meridian Research aerospace lab.
 * Intended for verifying integrity of protected backup archives in /var/archive/meridian/.
 *
 * Operational Security Boundary:
 * - Installed at: /usr/local/bin/pulse-helper
 * - Ownership: root:svc-pulse
 * - Permissions: 4750 (-rwsr-x---)
 * - Invoked by: svc-pulse (UID 1002)
 *
 * Vulnerable mode (default):
 * - Unsafe system() call with unsanitized archive_path allowing command injection.
 * Fixed mode (compiled with -DFIXED_MODE):
 * - Strict path whitelisting, metacharacter validation, privilege drop, and execv() execution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdbool.h>

#define HELPER_VERSION "0.1.0"
#define DEFAULT_ARCHIVE_DIR "/var/archive/meridian"

static void print_usage(const char *prog_name) {
    fprintf(stdout, "Usage: %s [OPTIONS]\n\n", prog_name);
    fprintf(stdout, "PULSE/1 Maintenance Helper (Meridian Research)\n\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "  --archive-check <path>  Verify integrity of specified backup archive\n");
    fprintf(stdout, "  -h, --help              Display this help message and exit\n");
    fprintf(stdout, "  -v, --version           Display version information and exit\n");
}

static void print_version(void) {
    fprintf(stdout, "pulse-helper version %s (Meridian Research Internal Tools)\n", HELPER_VERSION);
#ifdef FIXED_MODE
    fprintf(stdout, "Build mode: HARDENED (execv isolation, path whitelist, privilege drop)\n");
#else
    fprintf(stdout, "Build mode: STANDARD (legacy system() dispatch)\n");
#endif
}

#ifdef FIXED_MODE
static bool validate_archive_path(const char *path, const char *allowed_prefix) {
    if (!path || strlen(path) == 0) {
        fprintf(stderr, "[-] Error: empty archive path\n");
        return false;
    }

    // Reject shell metacharacters
    const char *disallowed = ";|&`$><\n\r()\"'\\*?[]{}";
    for (size_t i = 0; i < strlen(disallowed); i++) {
        if (strchr(path, disallowed[i]) != NULL) {
            fprintf(stderr, "[-] Error: illegal metacharacter '%c' in archive path\n", disallowed[i]);
            return false;
        }
    }

    // Reject directory traversal
    if (strstr(path, "..") != NULL) {
        fprintf(stderr, "[-] Error: directory traversal (..) forbidden\n");
        return false;
    }

    // Must start with allowed directory prefix
    size_t prefix_len = strlen(allowed_prefix);
    if (strncmp(path, allowed_prefix, prefix_len) != 0) {
        fprintf(stderr, "[-] Error: archive path must reside within %s\n", allowed_prefix);
        return false;
    }

    // Enforce strict directory boundary: prefix must end with '/' or path must have '/' immediately following prefix
    if (allowed_prefix[prefix_len - 1] != '/' && path[prefix_len] != '/' && path[prefix_len] != '\0') {
        fprintf(stderr, "[-] Error: archive path escapes %s directory boundary\n", allowed_prefix);
        return false;
    }

    return true;
}

static int execute_archive_check_fixed(const char *archive_path, const char *allowed_prefix) {
    if (!validate_archive_path(archive_path, allowed_prefix)) {
        return 1;
    }

    // Permanently drop elevated group and user privileges to real caller before executing external binary
    gid_t rgid = getgid();
    if (setgid(rgid) != 0) {
        perror("[-] Failed to drop group privileges");
        return 1;
    }

    uid_t ruid = getuid();
    if (setuid(ruid) != 0) {
        perror("[-] Failed to drop user privileges");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("[-] fork failed");
        return 1;
    }

    if (pid == 0) {
        // Child process: execute tar directly without shell
        char *const argv[] = {
            "tar",
            "-tzf",
            (char *)archive_path,
            NULL
        };
        // Redirect stdout/stderr to /dev/null
        if (freopen("/dev/null", "w", stdout) == NULL || freopen("/dev/null", "w", stderr) == NULL) {
            _exit(127);
        }
        // Direct execv calls with fixed absolute paths to avoid PATH search vulnerabilities
        execv("/usr/bin/tar", argv);
        execv("/bin/tar", argv);
        execvp("tar", argv);
        _exit(127);
    }

    // Parent process: await child termination
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("[-] waitpid failed");
        return 1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        fprintf(stdout, "[+] Archive integrity verified: %s\n", archive_path);
        return 0;
    } else {
        fprintf(stderr, "[-] Archive integrity verification failed for: %s\n", archive_path);
        return 1;
    }
}
#else
static int execute_archive_check_vulnerable(const char *archive_path) {
    /*
     * VULNERABLE IMPLEMENTATION (Scenario Ground Truth):
     * The argument is concatenated directly into a shell command buffer
     * and executed via system(). Because the binary is setuid root (4750),
     * shell metacharacters allow arbitrary command execution.
     *
     * Cross-platform Linux note: /bin/sh (dash on Ubuntu) automatically drops
     * privileges when ruid != euid unless -p is passed. To ensure the scenario
     * ground-truth behavior (attacker obtaining root to manipulate /var/log/audit/audit.log)
     * actually exhibits when run as a real setuid root binary, the helper explicitly
     * synchronizes real UID with effective UID (0) if running elevated.
     */
    if (geteuid() == 0) {
        if (setuid(0) != 0) {
            // Non-fatal if unprivileged in test harness
        }
    }

    char cmd[512];
    int written = snprintf(cmd, sizeof(cmd), "/bin/tar -tzf %s >/dev/null 2>&1", archive_path);
    if (written < 0 || (size_t)written >= sizeof(cmd)) {
        fprintf(stderr, "[-] Error: command buffer overflow\n");
        return 1;
    }

    int ret = system(cmd);
    if (ret == 0) {
        fprintf(stdout, "[+] Archive check completed: %s\n", archive_path);
        return 0;
    } else {
        fprintf(stderr, "[-] Archive check failed (code %d) for: %s\n", ret, archive_path);
        return 1;
    }
}
#endif

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *archive_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "--archive-check") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] Error: --archive-check requires a path argument\n");
                return 1;
            }
            archive_path = argv[++i];
        } else {
            fprintf(stderr, "[-] Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!archive_path) {
        fprintf(stderr, "[-] Error: No action specified\n");
        print_usage(argv[0]);
        return 1;
    }

    // Determine allowed archive directory (overridable in test environments)
    const char *archive_dir = getenv("PARALLAX_ARCHIVE_DIR");
    if (!archive_dir || strlen(archive_dir) == 0) {
        archive_dir = DEFAULT_ARCHIVE_DIR;
    }

#ifdef FIXED_MODE
    return execute_archive_check_fixed(archive_path, archive_dir);
#else
    (void)archive_dir;
    return execute_archive_check_vulnerable(archive_path);
#endif
}
