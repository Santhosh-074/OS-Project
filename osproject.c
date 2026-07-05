#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/statvfs.h>

#define RESET "\033[0m"
#define BOLD "\033[1m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define BG_RED "\033[41m"
#define BG_YEL "\033[43m"
#define BG_GRN "\033[42m"

#define MAX_PROCS 1024
#define TOP_N 10
#define LOG_FILE "/tmp/analyzer_alerts.log"
#define CORE_LOG_FILE "/tmp/analyzer_percore.log"
#define PROC_LOG_FILE "/tmp/analyzer_procs.log"

#define ALERT_CPU_WARN 60.0 /* WARNING  — yellow */
#define ALERT_CPU_CRIT 85.0 /* CRITICAL — red    */
#define ALERT_CPU_EMER 95.0 /* EMERGENCY— blink  */

#define ALERT_MEM_WARN 70.0
#define ALERT_MEM_CRIT 85.0
#define ALERT_MEM_EMER 95.0

#define ALERT_DISK 90.0

#define ALERT_PROC_CPU 20.0
#define ALERT_PROC_MEM 500

#define ALERT_BAT_LOW 20
#define ALERT_BAT_CRIT 10

typedef struct
{
    int pid;
    char name[256];
    char state;
    long utime;
    long stime;
    long utime_prev;
    long stime_prev;
    long vmrss;
    int priority;
    int nice;
    long num_threads;
    double cpu_percent;
    double mem_percent;
} ProcessInfo;

typedef struct
{
    long user, nice, system, idle, iowait, irq, softirq, steal;
    long total, idle_total;
} CoreStat;

void print_banner()
{
    printf(BOLD CYAN);
    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║     LINUX PERFORMANCE ANALYZER                       ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf(RESET);
}

void print_section(const char *title, const char *color)
{
    printf("\n%s%s━━━ %s ━━━%s\n", BOLD, color, title, RESET);
}

void print_bar(double value, int width)
{
    int filled = (int)((value / 100.0) * width);
    if (filled > width)
        filled = width;
    const char *color = (value > 80) ? RED : (value > 50) ? YELLOW
                                                          : GREEN;
    printf("[%s", color);
    for (int i = 0; i < width; i++)
        printf(i < filled ? "█" : "░");
    printf(RESET "] %5.1f%%", value);
}

/* Timestamp string into buf */
void get_timestamp(char *buf, int size)
{
    time_t t = time(NULL);
    char *ts = ctime(&t);
    ts[strlen(ts) - 1] = '\0';
    strncpy(buf, ts, size - 1);
    buf[size - 1] = '\0';
}

typedef enum
{
    LEVEL_OK = 0,
    LEVEL_WARN,
    LEVEL_CRIT,
    LEVEL_EMER
} AlertLevel;

void write_log(const char *logfile, const char *tag, const char *msg)
{
    FILE *fp = fopen(logfile, "a");
    if (!fp)
        return;
    char ts[64];
    get_timestamp(ts, sizeof(ts));
    fprintf(fp, "[%s] [%s] %s\n", ts, tag, msg);
    fclose(fp);
}

AlertLevel intelligent_alert(const char *label, double value,
                             double warn, double crit, double emer)
{
    char buf[256];
    char ts[64];
    get_timestamp(ts, sizeof(ts));

    if (value >= emer)
    {
        printf(BG_RED BOLD
               "\n  🚨 EMERGENCY: %s = %.1f%% (≥%.0f%%) — IMMEDIATE ACTION REQUIRED!\n" RESET,
               label, value, emer);
        snprintf(buf, sizeof(buf),
                 "EMERGENCY: %s=%.1f%% exceeded EMERGENCY threshold %.0f%%",
                 label, value, emer);
        write_log(LOG_FILE, "EMERGENCY", buf);
        return LEVEL_EMER;
    }
    else if (value >= crit)
    {
        printf(BG_RED BOLD
               "\n  ⛔ CRITICAL: %s = %.1f%% (≥%.0f%%) — Investigate immediately!\n" RESET,
               label, value, crit);
        snprintf(buf, sizeof(buf),
                 "CRITICAL: %s=%.1f%% exceeded CRITICAL threshold %.0f%%",
                 label, value, crit);
        write_log(LOG_FILE, "CRITICAL", buf);
        return LEVEL_CRIT;
    }
    else if (value >= warn)
    {
        printf(BG_YEL BOLD
               "\n  ⚠  WARNING: %s = %.1f%% (≥%.0f%%) — Monitor closely.\n" RESET,
               label, value, warn);
        snprintf(buf, sizeof(buf),
                 "WARNING: %s=%.1f%% exceeded WARNING threshold %.0f%%",
                 label, value, warn);
        write_log(LOG_FILE, "WARNING", buf);
        return LEVEL_WARN;
    }

    return LEVEL_OK;
}

void check_alert(const char *label, double value, double threshold)
{
    if (value >= threshold)
    {
        printf(BG_RED BOLD "\n  ⚠  ALERT: %s = %.1f%% (threshold: %.0f%%)\n" RESET,
               label, value, threshold);
        char buf[256];
        snprintf(buf, sizeof(buf), "ALERT: %s=%.1f%% exceeded %.0f%%",
                 label, value, threshold);
        write_log(LOG_FILE, "ALERT", buf);
    }
}

void get_cpu_times(long *total, long *idle_total)
{
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp)
    {
        perror("/proc/stat");
        exit(1);
    }
    long user, nice, system, idle, iowait, irq, softirq, steal;
    fscanf(fp, "cpu %ld %ld %ld %ld %ld %ld %ld %ld",
           &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
    fclose(fp);
    *idle_total = idle + iowait;
    *total = user + nice + system + idle + iowait + irq + softirq + steal;
}

double calculate_cpu_usage()
{
    long t1, id1, t2, id2;
    get_cpu_times(&t1, &id1);
    sleep(1);
    get_cpu_times(&t2, &id2);
    long td = t2 - t1, id = id2 - id1;
    return td == 0 ? 0.0 : (double)(td - id) / td * 100.0;
}

int read_core_stats(CoreStat *cores, int max)
{
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp)
        return 0;
    char line[256];
    fgets(line, sizeof(line), fp); /* skip aggregate */
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < max)
    {
        if (strncmp(line, "cpu", 3) != 0 || !isdigit(line[3]))
            break;
        CoreStat *c = &cores[count];
        sscanf(line, "cpu%*d %ld %ld %ld %ld %ld %ld %ld %ld",
               &c->user, &c->nice, &c->system, &c->idle,
               &c->iowait, &c->irq, &c->softirq, &c->steal);
        c->idle_total = c->idle + c->iowait;
        c->total = c->user + c->nice + c->system + c->idle +
                   c->iowait + c->irq + c->softirq + c->steal;
        count++;
    }
    fclose(fp);
    return count;
}

void show_cpu_details()
{
    print_section("CPU INFORMATION", CYAN);

    FILE *fp = fopen("/proc/stat", "r");
    if (!fp)
        return;

    long user, nice, sys, idle, iowait, irq, softirq, steal;
    fscanf(fp, "cpu %ld %ld %ld %ld %ld %ld %ld %ld",
           &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal);
    fclose(fp);

    long total_jiffies = user + nice + sys + idle + iowait + irq + softirq + steal;

    double to_min = 6000.0;

    printf("  %-20s : %8.2f min\n", "User Time", (double)user / to_min);
    printf("  %-20s : %8.2f min\n", "Nice Time", (double)nice / to_min);
    printf("  %-20s : %8.2f min\n", "System Time", (double)sys / to_min);
    printf("  %-20s : %8.2f min\n", "Idle Time", (double)idle / to_min);
    printf("  %-20s : %8.2f min\n", "I/O Wait", (double)iowait / to_min);
    printf("  %-20s : %8.2f min\n", "IRQ Time", (double)irq / to_min);
    printf("  %-20s : %8.2f min\n", "SoftIRQ Time", (double)softirq / to_min);
    printf("  %-20s : %8.2f min\n", "Steal Time", (double)steal / to_min);
    printf("  %-20s : %8.2f min\n", "Total", (double)total_jiffies / to_min);

    fp = fopen("/proc/cpuinfo", "r");
    if (fp)
    {
        char line[256];
        while (fgets(line, sizeof(line), fp))
            if (strncmp(line, "model name", 10) == 0)
            {
                char *p = strchr(line, ':');
                if (p)
                    printf("\n  " BOLD "CPU Model     :" RESET " %s", p + 2);
                break;
            }
        fclose(fp);
    }

    print_section("CPU EVENTS", CYAN);
    fp = fopen("/proc/stat", "r");
    if (fp)
    {
        char line[256];
        while (fgets(line, sizeof(line), fp))
        {
            if (strncmp(line, "ctxt", 4) == 0)
            {
                long v;
                sscanf(line + 5, "%ld", &v);
                printf("  Context Switches   : %ld\n", v);
            }
            if (strncmp(line, "intr", 4) == 0)
            {
                long v;
                sscanf(line + 5, "%ld", &v);
                printf("  Total Interrupts   : %ld\n", v);
            }
            if (strncmp(line, "processes", 9) == 0)
            {
                long v;
                sscanf(line + 10, "%ld", &v);
                printf("  Processes Forked   : %ld\n", v);
            }
            if (strncmp(line, "procs_running", 13) == 0)
            {
                int v;
                sscanf(line + 14, "%d", &v);
                printf("  Procs Running Now  : %d\n", v);
            }
            if (strncmp(line, "procs_blocked", 13) == 0)
            {
                int v;
                sscanf(line + 14, "%d", &v);
                printf("  Procs Blocked(I/O) : %d\n", v);
            }
        }
        fclose(fp);
    }

    printf("\n  Measuring real-time CPU usage (1s sample)...\n");
    double usage = calculate_cpu_usage();
    printf("  " BOLD "Overall CPU : " RESET);
    print_bar(usage, 40);
    printf("\n");

    /* Intelligent 3-level CPU alert */
    intelligent_alert("CPU", usage, ALERT_CPU_WARN, ALERT_CPU_CRIT, ALERT_CPU_EMER);
}

void show_percore_tracking()
{
    print_section("PER-CORE PERFORMANCE TRACKING", CYAN);
    printf("  Taking 1s delta sample per core...\n\n");

    CoreStat before[64], after[64];
    int n = read_core_stats(before, 64);
    if (n == 0)
    {
        printf("  No per-core data available.\n");
        return;
    }
    sleep(1);
    read_core_stats(after, 64);

    char ts[64];
    get_timestamp(ts, sizeof(ts));

    FILE *logfp = fopen(CORE_LOG_FILE, "a");
    if (logfp)
        fprintf(logfp, "\n[%s] Per-Core Snapshot\n", ts);

    printf("  %-8s %-36s %8s %8s %8s %8s\n",
           "CORE", "USAGE BAR", "USER%", "SYS%", "IOWAIT%", "IDLE%");
    printf("  %s\n", "────────────────────────────────────────────────────────────────────");

    for (int i = 0; i < n; i++)
    {
        long dtotal = after[i].total - before[i].total;
        long didle = after[i].idle_total - before[i].idle_total;
        long duser = after[i].user - before[i].user;
        long dsys = after[i].system - before[i].system;
        long diow = after[i].iowait - before[i].iowait;

        if (dtotal == 0)
            dtotal = 1;

        double usage = (double)(dtotal - didle) / dtotal * 100.0;
        double user_p = (double)duser / dtotal * 100.0;
        double sys_p = (double)dsys / dtotal * 100.0;
        double iow_p = (double)diow / dtotal * 100.0;
        double idle_p = (double)didle / dtotal * 100.0;

        printf("  Core %-3d ", i);
        print_bar(usage, 30);
        printf("  %6.1f%%  %6.1f%%  %6.1f%%  %6.1f%%\n",
               user_p, sys_p, iow_p, idle_p);

        if (logfp)
        {
            fprintf(logfp,
                    "  Core%d: usage=%.1f%% user=%.1f%% sys=%.1f%% iowait=%.1f%% idle=%.1f%%\n",
                    i, usage, user_p, sys_p, iow_p, idle_p);
        }

        if (usage >= ALERT_CPU_CRIT)
        {
            printf(RED "  ⛔ CRITICAL: Core %d at %.1f%% — possible thread hotspot!\n" RESET,
                   i, usage);
            char buf[128];
            snprintf(buf, sizeof(buf),
                     "CRITICAL: Core%d usage=%.1f%% exceeded %.0f%%",
                     i, usage, ALERT_CPU_CRIT);
            write_log(CORE_LOG_FILE, "CORE-ALERT", buf);
        }
        else if (usage >= ALERT_CPU_WARN)
        {
            printf(YELLOW "  ⚠  WARNING: Core %d at %.1f%%\n" RESET, i, usage);
        }
    }

    if (logfp)
        fclose(logfp);
    printf(GREEN "\n  Per-core data logged to: %s\n" RESET, CORE_LOG_FILE);
}

void show_uptime()
{
    print_section("SYSTEM UPTIME", GREEN);
    FILE *fp = fopen("/proc/uptime", "r");
    if (!fp)
    {
        perror("/proc/uptime");
        return;
    }
    double up, idle_s;
    fscanf(fp, "%lf %lf", &up, &idle_s);
    fclose(fp);
    int days = (int)up / 86400, hours = ((int)up % 86400) / 3600,
        mins = ((int)up % 3600) / 60, secs = (int)up % 60;
    printf("  Uptime        : %d days, %02d:%02d:%02d\n", days, hours, mins, secs);
    printf("  Total Seconds : %.0f\n", up);
    printf("  CPU Idle Time : %.0f s  (%.1f%% of uptime)\n",
           idle_s, up > 0 ? idle_s / up * 100.0 : 0);
}

void show_loadavg()
{
    print_section("LOAD AVERAGE", YELLOW);
    FILE *fp = fopen("/proc/loadavg", "r");
    if (!fp)
        return;
    double l1, l5, l15;
    int running, total;
    fscanf(fp, "%lf %lf %lf %d/%d", &l1, &l5, &l15, &running, &total);
    fclose(fp);

    int cores = 0;
    fp = fopen("/proc/cpuinfo", "r");
    if (fp)
    {
        char line[256];
        while (fgets(line, sizeof(line), fp))
            if (strncmp(line, "processor", 9) == 0)
                cores++;
        fclose(fp);
    }
    if (cores == 0)
        cores = 1;

    printf("  1  Min Avg : %5.2f  ", l1);
    print_bar(l1 / cores * 100, 30);
    printf("\n");
    printf("  5  Min Avg : %5.2f  ", l5);
    print_bar(l5 / cores * 100, 30);
    printf("\n");
    printf("  15 Min Avg : %5.2f  ", l15);
    print_bar(l15 / cores * 100, 30);
    printf("\n");
    printf("\n  Running Threads : %d / %d\n", running, total);
    printf("  CPU Cores       : %d\n", cores);
    if (l1 > cores)
        printf(RED "\n  ⚠  Load exceeds core count — system overloaded!\n" RESET);
}

void show_memory()
{
    print_section("MEMORY INFORMATION", BLUE);
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp)
        return;

    char label[64];
    long value;
    long total = 0, free_m = 0, available = 0, buffers = 0, cached = 0;
    long swap_total = 0, swap_free = 0, dirty = 0, writeback = 0, mapped = 0, anon = 0, shmem = 0;

    while (fscanf(fp, "%63s %ld kB\n", label, &value) == 2)
    {
        if (!strcmp(label, "MemTotal:"))
            total = value;
        if (!strcmp(label, "MemFree:"))
            free_m = value;
        if (!strcmp(label, "MemAvailable:"))
            available = value;
        if (!strcmp(label, "Buffers:"))
            buffers = value;
        if (!strcmp(label, "Cached:"))
            cached = value;
        if (!strcmp(label, "SwapTotal:"))
            swap_total = value;
        if (!strcmp(label, "SwapFree:"))
            swap_free = value;
        if (!strcmp(label, "Dirty:"))
            dirty = value;
        if (!strcmp(label, "Writeback:"))
            writeback = value;
        if (!strcmp(label, "Mapped:"))
            mapped = value;
        if (!strcmp(label, "AnonPages:"))
            anon = value;
        if (!strcmp(label, "Shmem:"))
            shmem = value;
    }
    fclose(fp);

    long used = total - free_m - buffers - cached;
    double mem_pct = total ? (double)used / total * 100.0 : 0;
    double swap_pct = swap_total ? (double)(swap_total - swap_free) / swap_total * 100.0 : 0;

    printf("  RAM  Usage : ");
    print_bar(mem_pct, 40);
    printf("\n");
    printf("  Swap Usage : ");
    print_bar(swap_pct, 40);
    printf("\n\n");

    printf("  %-22s : %8.2f MB\n", "Total RAM", total / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Used RAM", used / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Free RAM", free_m / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Available", available / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Buffers", buffers / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Cached", cached / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Shared(shmem)", shmem / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Anonymous", anon / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Mapped", mapped / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Dirty Pages", dirty / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Writeback", writeback / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Swap Total", swap_total / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Swap Used", (swap_total - swap_free) / 1024.0);
    printf("  %-22s : %8.2f MB\n", "Swap Free", swap_free / 1024.0);

    /* Intelligent 3-level memory alert */
    intelligent_alert("Memory", mem_pct, ALERT_MEM_WARN, ALERT_MEM_CRIT, ALERT_MEM_EMER);

    if (swap_total > 0 && swap_pct > 50)
        printf(YELLOW "\n  ⚠  High swap (%.1f%%) — memory pressure detected!\n" RESET, swap_pct);
    if (dirty > 102400)
        printf(YELLOW "  ⚠  High dirty pages (%.1f MB) — disk flush pending\n" RESET, dirty / 1024.0);
}

int read_proc_ticks(int pid, long *utime, long *stime)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;
    long dummy;
    long lnice;
    int iprio;
    char name[256];
    char state;
    fscanf(fp,
           "%*d %255s %c %ld %ld %ld %ld %d %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld",
           name, &state,
           &dummy, &dummy, &dummy, &dummy,
           &iprio, &dummy, &dummy, &dummy, &dummy,
           utime, stime,
           &dummy, &dummy, &dummy, &lnice, &dummy);
    fclose(fp);
    return 1;
}

void show_process_resource_tracking()
{
    print_section("PER-PROCESS RESOURCE TRACKING", MAGENTA);
    printf("  Sampling CPU usage per process (1s delta)...\n\n");

    /* Get total RAM for mem% calculation */
    long total_ram = 0;
    FILE *fp = fopen("/proc/meminfo", "r");
    if (fp)
    {
        char lbl[64];
        long v;
        while (fscanf(fp, "%63s %ld kB\n", lbl, &v) == 2)
            if (!strcmp(lbl, "MemTotal:"))
            {
                total_ram = v;
                break;
            }
        fclose(fp);
    }
    if (total_ram == 0)
        total_ram = 1;

    long sys_total1, sys_idle1, sys_total2, sys_idle2;
    get_cpu_times(&sys_total1, &sys_idle1);

    ProcessInfo procs[MAX_PROCS];
    int count = 0;
    DIR *dir = opendir("/proc");
    if (!dir)
        return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < MAX_PROCS)
    {
        int pid = atoi(entry->d_name);
        if (pid <= 0)
            continue;
        procs[count].pid = pid;
        read_proc_ticks(pid, &procs[count].utime, &procs[count].stime);
        count++;
    }
    closedir(dir);

    sleep(1);

    get_cpu_times(&sys_total2, &sys_idle2);
    long sys_delta = sys_total2 - sys_total1;
    if (sys_delta == 0)
        sys_delta = 1;

    for (int i = 0; i < count; i++)
    {
        long utime2 = 0, stime2 = 0;
        if (!read_proc_ticks(procs[i].pid, &utime2, &stime2))
            continue;

        long proc_delta = (utime2 - procs[i].utime) + (stime2 - procs[i].stime);
        procs[i].cpu_percent = (double)proc_delta / sys_delta * 100.0;
        procs[i].utime = utime2;
        procs[i].stime = stime2;

        char path[128];
        snprintf(path, sizeof(path), "/proc/%d/status", procs[i].pid);
        FILE *sfp = fopen(path, "r");
        procs[i].vmrss = 0;
        strcpy(procs[i].name, "?");
        if (sfp)
        {
            char line[256];
            while (fgets(line, sizeof(line), sfp))
            {
                if (strncmp(line, "Name:", 5) == 0)
                    sscanf(line + 5, "%255s", procs[i].name);
                if (strncmp(line, "VmRSS:", 6) == 0)
                    sscanf(line + 6, "%ld", &procs[i].vmrss);
            }
            fclose(sfp);
        }
        procs[i].mem_percent = (double)procs[i].vmrss / total_ram * 100.0;
    }

    for (int i = 0; i < count - 1; i++)
        for (int j = i + 1; j < count; j++)
            if (procs[j].cpu_percent > procs[i].cpu_percent)
            {
                ProcessInfo tmp = procs[i];
                procs[i] = procs[j];
                procs[j] = tmp;
            }

    printf("  %-6s %-22s %10s %10s %10s\n",
           "PID", "NAME", "CPU%", "MEM(MB)", "MEM%");
    printf("  %s\n", "──────────────────────────────────────────────────────────");

    FILE *plog = fopen(PROC_LOG_FILE, "a");
    char ts[64];
    get_timestamp(ts, sizeof(ts));
    if (plog)
        fprintf(plog, "\n[%s] Process Resource Snapshot\n", ts);

    int shown = 0;
    for (int i = 0; i < count && shown < TOP_N; i++)
    {
        if (procs[i].cpu_percent < 0.01 && procs[i].vmrss == 0)
            continue;

        const char *cpu_color = procs[i].cpu_percent >= ALERT_PROC_CPU ? RED : procs[i].cpu_percent >= 5.0 ? YELLOW
                                                                                                           : GREEN;
        const char *mem_color = (procs[i].vmrss / 1024) >= ALERT_PROC_MEM ? RED : (procs[i].vmrss / 1024) >= 200 ? YELLOW
                                                                                                                 : GREEN;

        printf("  %-6d %-22s %s%9.2f%%" RESET " %s%9.2f MB%s  %s%.2f%%\n" RESET,
               procs[i].pid, procs[i].name,
               cpu_color, procs[i].cpu_percent,
               mem_color, procs[i].vmrss / 1024.0, RESET,
               mem_color, procs[i].mem_percent);

        if (procs[i].cpu_percent >= ALERT_PROC_CPU)
        {
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "HIGH CPU: PID=%d name=%.40s cpu=%.1f%%",
                     procs[i].pid, procs[i].name, procs[i].cpu_percent);
            write_log(PROC_LOG_FILE, "PROC-CPU", buf);
            printf(RED "  ⛔ PID %d (%s) using %.1f%% CPU!\n" RESET,
                   procs[i].pid, procs[i].name, procs[i].cpu_percent);
        }
        if ((procs[i].vmrss / 1024) >= ALERT_PROC_MEM)
        {
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "HIGH MEM: PID=%d name=%.40s mem=%.1fMB",
                     procs[i].pid, procs[i].name, procs[i].vmrss / 1024.0);
            write_log(PROC_LOG_FILE, "PROC-MEM", buf);
            printf(RED "  ⛔ PID %d (%s) using %.1f MB RAM!\n" RESET,
                   procs[i].pid, procs[i].name, procs[i].vmrss / 1024.0);
        }

        if (plog)
            fprintf(plog, "  PID=%-6d %-22s CPU=%.2f%%  MEM=%.2fMB\n",
                    procs[i].pid, procs[i].name,
                    procs[i].cpu_percent, procs[i].vmrss / 1024.0);
        shown++;
    }
    if (plog)
        fclose(plog);
    printf(GREEN "\n  Process tracking logged to: %s\n" RESET, PROC_LOG_FILE);
}

int read_all_processes(ProcessInfo *procs, int max)
{
    DIR *dir = opendir("/proc");
    if (!dir)
        return 0;
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL && count < max)
    {
        if (atoi(entry->d_name) <= 0)
            continue;
        ProcessInfo *p = &procs[count];
        p->pid = atoi(entry->d_name);
        p->vmrss = 0;
        char path[512];
        snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
        FILE *fp = fopen(path, "r");
        if (!fp)
            continue;
        long dummy;
        long lnice;
        fscanf(fp,
               "%d %255s %c %ld %ld %ld %ld %d %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld",
               &p->pid, p->name, &p->state,
               &dummy, &dummy, &dummy, &dummy,
               &p->priority, &dummy, &dummy, &dummy, &dummy,
               &p->utime, &p->stime,
               &dummy, &dummy, &dummy, &lnice, &p->num_threads);
        p->nice = (int)lnice;
        fclose(fp);
        int len = strlen(p->name);
        if (p->name[0] == '(' && p->name[len - 1] == ')')
        {
            p->name[len - 1] = '\0';
            memmove(p->name, p->name + 1, len);
        }
        snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);
        fp = fopen(path, "r");
        if (fp)
        {
            char line[256];
            while (fgets(line, sizeof(line), fp))
                if (strncmp(line, "VmRSS:", 6) == 0)
                {
                    sscanf(line + 6, "%ld", &p->vmrss);
                    break;
                }
            fclose(fp);
        }
        count++;
    }
    closedir(dir);
    return count;
}

void show_process_stats()
{
    print_section("PROCESS ANALYSIS", MAGENTA);
    ProcessInfo procs[MAX_PROCS];
    int total = read_all_processes(procs, MAX_PROCS);
    int running = 0, sleeping = 0, zombie = 0, stopped = 0, disk_sleep = 0;
    for (int i = 0; i < total; i++)
    {
        switch (procs[i].state)
        {
        case 'R':
            running++;
            break;
        case 'S':
            sleeping++;
            break;
        case 'Z':
            zombie++;
            break;
        case 'T':
            stopped++;
            break;
        case 'D':
            disk_sleep++;
            break;
        }
    }
    printf("  Total Processes       : " BOLD "%d\n" RESET, total);
    printf("  " GREEN "Running  (R)          : %d\n" RESET, running);
    printf("  " BLUE "Sleeping (S)          : %d\n" RESET, sleeping);
    printf("  " YELLOW "Disk Sleep (D)        : %d\n" RESET, disk_sleep);
    printf("  " CYAN "Stopped  (T)          : %d\n" RESET, stopped);
    printf("  " RED "Zombie   (Z)          : %d\n" RESET, zombie);
    if (zombie > 0)
        printf(RED "\n  ⚠  %d zombie(s) — parent not calling wait()\n" RESET, zombie);
}

int cmp_mem(const void *a, const void *b) { return (int)(((ProcessInfo *)b)->vmrss - ((ProcessInfo *)a)->vmrss); }
int cmp_cpu(const void *a, const void *b)
{
    long at = ((ProcessInfo *)a)->utime + ((ProcessInfo *)a)->stime;
    long bt = ((ProcessInfo *)b)->utime + ((ProcessInfo *)b)->stime;
    return (int)(bt - at);
}

void show_top_processes()
{
    ProcessInfo procs[MAX_PROCS];
    int total = read_all_processes(procs, MAX_PROCS);
    print_section("TOP PROCESSES BY MEMORY", CYAN);
    qsort(procs, total, sizeof(ProcessInfo), cmp_mem);
    printf("  %-6s %-22s %-6s %10s %8s %5s\n", "PID", "NAME", "STATE", "MEM(MB)", "THREADS", "NICE");
    printf("  %s\n", "──────────────────────────────────────────────────────");
    for (int i = 0; i < TOP_N && i < total; i++)
    {
        ProcessInfo *p = &procs[i];
        const char *sc = (p->state == 'R') ? GREEN : (p->state == 'Z') ? RED
                                                                       : RESET;
        printf("  %-6d %-22s %s%-6c" RESET " %10.2f %8ld %5d\n",
               p->pid, p->name, sc, p->state, p->vmrss / 1024.0, p->num_threads, p->nice);
    }
    print_section("TOP PROCESSES BY CPU TIME", CYAN);
    qsort(procs, total, sizeof(ProcessInfo), cmp_cpu);
    printf("  %-6s %-22s %12s %12s %12s\n", "PID", "NAME", "USER_TIME", "SYS_TIME", "TOTAL");
    printf("  %s\n", "────────────────────────────────────────────────────────");
    for (int i = 0; i < TOP_N && i < total; i++)
    {
        ProcessInfo *p = &procs[i];
        printf("  %-6d %-22s %12ld %12ld %12ld\n",
               p->pid, p->name, p->utime, p->stime, p->utime + p->stime);
    }
}

int read_battery_value(const char *bat, const char *field, char *out, int size)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/power_supply/%s/%s", bat, field);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;
    fgets(out, size, fp);
    fclose(fp);
    /* strip newline */
    int len = strlen(out);
    if (len > 0 && out[len - 1] == '\n')
        out[len - 1] = '\0';
    return 1;
}

void show_battery()
{
    print_section("BATTERY USAGE MONITORING", YELLOW);

    /* Try BAT0 then BAT1 */
    const char *bat_names[] = {"BAT0", "BAT1", "battery", "BAT", "CMB0", NULL};
    const char *bat = NULL;
    char tmp[64];

    for (int i = 0; bat_names[i] != NULL; i++)
    {
        if (read_battery_value(bat_names[i], "capacity", tmp, sizeof(tmp)))
        {
            bat = bat_names[i];
            break;
        }
    }

    if (!bat)
    {
        printf("  Battery not found.\n");
        printf("  (Running on desktop/VM or battery path not accessible)\n\n");
        printf("  " BOLD "What this feature monitors on a laptop:\n" RESET);
        printf("  %-28s : /sys/class/power_supply/BAT0/capacity\n", "Battery Capacity %%");
        printf("  %-28s : /sys/class/power_supply/BAT0/status\n", "Charge Status");
        printf("  %-28s : /sys/class/power_supply/BAT0/energy_now\n", "Current Energy");
        printf("  %-28s : /sys/class/power_supply/BAT0/energy_full\n", "Full Capacity");
        printf("  %-28s : /sys/class/power_supply/BAT0/voltage_now\n", "Voltage");
        printf("  %-28s : /sys/class/power_supply/BAT0/health\n", "Health");
        printf("  %-28s : /sys/class/power_supply/BAT0/cycle_count\n", "Charge Cycles");
        return;
    }

    printf("  Battery Found     : %s\n\n", bat);

    /* Capacity */
    int capacity = 0;
    if (read_battery_value(bat, "capacity", tmp, sizeof(tmp)))
    {
        capacity = atoi(tmp);
        printf("  Capacity          : ");
        print_bar((double)capacity, 40);
        printf("\n");
    }

    char status[64] = "Unknown";
    read_battery_value(bat, "status", status, sizeof(status));
    const char *sc = strcmp(status, "Charging") == 0 ? GREEN : strcmp(status, "Full") == 0      ? BG_GRN
                                                           : strcmp(status, "Discharging") == 0 ? YELLOW
                                                                                                : RESET;
    printf("  Status            : %s%s%s\n", sc, status, RESET);

    /* Energy now / full */
    char en_now[32] = "N/A", en_full[32] = "N/A";
    read_battery_value(bat, "energy_now", en_now, sizeof(en_now));
    read_battery_value(bat, "energy_full", en_full, sizeof(en_full));
    if (strcmp(en_now, "N/A") != 0 && strcmp(en_full, "N/A") != 0)
    {
        long enow = atol(en_now) / 1000;
        long efull = atol(en_full) / 1000;
        printf("  Energy Now        : %ld mWh\n", enow);
        printf("  Energy Full       : %ld mWh\n", efull);
        if (efull > 0)
        {
            double wear = 100.0 - ((double)enow / efull * 100.0);
            printf("  Wear Level        : %.1f%% capacity lost\n", wear);
        }
    }

    char ch_now[32] = "", ch_full[32] = "";
    if (read_battery_value(bat, "charge_now", ch_now, sizeof(ch_now)) &&
        read_battery_value(bat, "charge_full", ch_full, sizeof(ch_full)))
    {
        long cnow = atol(ch_now) / 1000;
        long cfull = atol(ch_full) / 1000;
        printf("  Charge Now        : %ld mAh\n", cnow);
        printf("  Charge Full       : %ld mAh\n", cfull);
    }

    char volt[32] = "";
    if (read_battery_value(bat, "voltage_now", volt, sizeof(volt)))
    {
        double v = atol(volt) / 1e6;
        printf("  Voltage           : %.3f V\n", v);
    }

    char health[32] = "N/A";
    read_battery_value(bat, "capacity_level", health, sizeof(health));
    printf("  Capacity Level    : %s\n", health);

    char tech[32] = "N/A";
    read_battery_value(bat, "technology", tech, sizeof(tech));
    printf("  Technology        : %s\n", tech);

    char cycles[32] = "";
    if (read_battery_value(bat, "cycle_count", cycles, sizeof(cycles)))
        printf("  Charge Cycles     : %s\n", cycles);

    char power[32] = "";
    if (read_battery_value(bat, "power_now", power, sizeof(power)))
    {
        double pw = atol(power) / 1e6;
        printf("  Power Draw        : %.2f W\n", pw);
        if (strcmp(status, "Discharging") == 0 && pw > 0)
        {
            char en2[32] = "";
            if (read_battery_value(bat, "energy_now", en2, sizeof(en2)))
            {
                double e = atol(en2) / 1e6;
                double hrs = e / pw;
                printf("  Est. Time Left    : %.1f hours (%.0f min)\n", hrs, hrs * 60);
            }
        }
    }

    if (capacity > 0)
    {
        if (capacity <= ALERT_BAT_CRIT)
        {
            printf(BG_RED BOLD
                   "\n  CRITICAL: Battery at %d%% — Connect charger immediately!\n" RESET,
                   capacity);
            char buf[128];
            snprintf(buf, sizeof(buf), "CRITICAL: Battery=%d%% (threshold=%d%%)",
                     capacity, ALERT_BAT_CRIT);
            write_log(LOG_FILE, "BATTERY", buf);
        }
        else if (capacity <= ALERT_BAT_LOW)
        {
            printf(BG_YEL BOLD
                   "\n  ⚠  WARNING: Battery at %d%% — Connect charger soon.\n" RESET,
                   capacity);
            char buf[128];
            snprintf(buf, sizeof(buf), "WARNING: Battery=%d%% (threshold=%d%%)",
                     capacity, ALERT_BAT_LOW);
            write_log(LOG_FILE, "BATTERY", buf);
        }
        else if (strcmp(status, "Discharging") == 0)
        {
            printf(YELLOW "\n  Battery is discharging (%d%% remaining)\n" RESET, capacity);
        }
        else if (strcmp(status, "Charging") == 0)
        {
            printf(GREEN "\n  Battery is charging (%d%%)\n" RESET, capacity);
        }
        else if (strcmp(status, "Full") == 0)
        {
            printf(BG_GRN BOLD "\n  Battery fully charged (100%%)\n" RESET);
        }
    }
}

void show_network()
{
    print_section("NETWORK INTERFACES", BLUE);
    FILE *fp = fopen("/proc/net/dev", "r");
    if (!fp)
        return;
    char line[512];
    fgets(line, sizeof(line), fp);
    fgets(line, sizeof(line), fp);
    printf("  %-12s %14s %14s %12s %12s %8s %8s\n",
           "INTERFACE", "RX_BYTES", "TX_BYTES", "RX_PKTS", "TX_PKTS", "RX_ERR", "TX_ERR");
    printf("  %s\n", "──────────────────────────────────────────────────────────────────────────");
    while (fgets(line, sizeof(line), fp))
    {
        char iface[32];
        long rb, rp, re, tb, tp, te;
        sscanf(line, " %31[^:]: %ld %ld %ld %*d %*d %*d %*d %*d %ld %ld %ld",
               iface, &rb, &rp, &re, &tb, &tp, &te);
        printf("  %-12s %14ld %14ld %12ld %12ld %8ld %8ld\n", iface, rb, tb, rp, tp, re, te);
    }
    fclose(fp);

    print_section("TCP CONNECTION STATES", BLUE);
    fp = fopen("/proc/net/tcp", "r");
    if (!fp)
        return;
    fgets(line, sizeof(line), fp);
    int est = 0, lst = 0, tw = 0, cw = 0, tot = 0;
    while (fgets(line, sizeof(line), fp))
    {
        unsigned int state;
        sscanf(line, " %*d: %*s %*s %X", &state);
        tot++;
        if (state == 0x01)
            est++;
        else if (state == 0x0A)
            lst++;
        else if (state == 0x06)
            tw++;
        else if (state == 0x08)
            cw++;
    }
    fclose(fp);
    printf("  Total TCP      : %d\n", tot);
    printf("  " GREEN "ESTABLISHED  : %d\n" RESET, est);
    printf("  " CYAN "LISTEN       : %d\n" RESET, lst);
    printf("  " YELLOW "TIME_WAIT    : %d\n" RESET, tw);
    printf("  " MAGENTA "CLOSE_WAIT  : %d\n" RESET, cw);
    if (tw > 100)
        printf(YELLOW "  ⚠  High TIME_WAIT (%d) — connection exhaustion risk\n" RESET, tw);
    if (cw > 50)
        printf(RED "  ⚠  High CLOSE_WAIT (%d) — possible connection leak\n" RESET, cw);
}

void show_disk()
{
    print_section("DISK USAGE", YELLOW);
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp)
        return;
    char line[512];
    printf("  %-18s %-14s %-8s %10s %10s %10s  %s\n",
           "DEVICE", "MOUNT", "FSTYPE", "TOTAL(GB)", "USED(GB)", "FREE(GB)", "USE%%");
    printf("  %s\n", "──────────────────────────────────────────────────────────────────────────");
    while (fgets(line, sizeof(line), fp))
    {
        char dev[64], mnt[128], fstype[32], opts[256];
        sscanf(line, "%63s %127s %31s %255s", dev, mnt, fstype, opts);
        if (strncmp(fstype, "proc", 4) == 0 || strncmp(fstype, "sysfs", 5) == 0 ||
            strncmp(fstype, "tmpfs", 5) == 0 || strncmp(fstype, "devtmpfs", 8) == 0 ||
            strncmp(fstype, "cgroup", 6) == 0 || strncmp(fstype, "overlay", 7) == 0)
            continue;
        struct statvfs sv;
        if (statvfs(mnt, &sv) != 0)
            continue;
        unsigned long long tot2 = (unsigned long long)sv.f_blocks * sv.f_frsize;
        unsigned long long fre = (unsigned long long)sv.f_bfree * sv.f_frsize;
        unsigned long long use = tot2 - fre;
        double pct = tot2 ? (double)use / tot2 * 100.0 : 0;
        const char *col = pct > 90 ? RED : pct > 70 ? YELLOW
                                                    : GREEN;
        printf("  %-18s %-14s %-8s %10.2f %10.2f %10.2f  %s%.1f%%\n" RESET,
               dev, mnt, fstype, tot2 / 1e9, use / 1e9, fre / 1e9, col, pct);
        check_alert(mnt, pct, ALERT_DISK);
    }
    fclose(fp);

    print_section("DISK I/O STATISTICS", YELLOW);
    fp = fopen("/proc/diskstats", "r");
    if (!fp)
        return;
    printf("  %-14s %12s %12s %14s %14s\n", "DEVICE", "READS", "WRITES", "READ_MB", "WRITE_MB");
    printf("  %s\n", "────────────────────────────────────────────────────────────");
    while (fgets(line, sizeof(line), fp))
    {
        unsigned int maj, min2;
        char dn[32];
        long rd, rm, rs, rms, wr, wm, ws, wms;
        sscanf(line, "%u %u %31s %ld %ld %ld %ld %ld %ld %ld %ld",
               &maj, &min2, dn, &rd, &rm, &rs, &rms, &wr, &wm, &ws, &wms);
        if (rd == 0 && wr == 0)
            continue;
        printf("  %-14s %12ld %12ld %14.2f %14.2f\n", dn, rd, wr, rs / 2048.0, ws / 2048.0);
    }
    fclose(fp);
}

void show_fd_info()
{
    print_section("FILE DESCRIPTORS & KERNEL LIMITS", CYAN);
    FILE *fp = fopen("/proc/sys/fs/file-nr", "r");
    if (fp)
    {
        long al, un, mx;
        fscanf(fp, "%ld %ld %ld", &al, &un, &mx);
        fclose(fp);
        long used = al - un;
        double pct = mx ? (double)used / mx * 100.0 : 0;
        printf("  %-24s : %ld\n", "FD Allocated", al);
        printf("  %-24s : %ld\n", "FD In Use", used);
        printf("  %-24s : %ld\n", "FD Max", mx);
        printf("  FD Usage          : ");
        print_bar(pct, 30);
        printf("\n");
        if (pct > 80)
            printf(RED "\n  ⚠  FD >80%% — risk of 'too many open files'!\n" RESET);
    }
    fp = fopen("/proc/sys/kernel/pid_max", "r");
    if (fp)
    {
        int v;
        fscanf(fp, "%d", &v);
        fclose(fp);
        printf("  %-24s : %d\n", "Max PID", v);
    }
    fp = fopen("/proc/sys/kernel/threads-max", "r");
    if (fp)
    {
        int v;
        fscanf(fp, "%d", &v);
        fclose(fp);
        printf("  %-24s : %d\n", "Max Threads", v);
    }
    fp = fopen("/proc/sys/vm/swappiness", "r");
    if (fp)
    {
        int v;
        fscanf(fp, "%d", &v);
        fclose(fp);
        printf("  %-24s : %d\n", "VM Swappiness", v);
    }
    fp = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (fp)
    {
        int v;
        fscanf(fp, "%d", &v);
        fclose(fp);
        printf("  %-24s : %s\n", "IP Forwarding", v ? "Enabled" : "Disabled");
    }
}

void realtime_monitor()
{
    print_section("REAL-TIME MONITOR (5 snapshots × 2s)", GREEN);
    printf("  Sampling system metrics...\n\n");
    for (int i = 1; i <= 5; i++)
    {
        long t1, id1, t2, id2;
        get_cpu_times(&t1, &id1);
        sleep(2);
        get_cpu_times(&t2, &id2);
        long td = t2 - t1, id = id2 - id1;
        double cpu_pct = td ? (double)(td - id) / td * 100.0 : 0;
        FILE *fp = fopen("/proc/meminfo", "r");
        long mt = 0, mf = 0, mb = 0, mc = 0;
        if (fp)
        {
            char l[64];
            long v;
            while (fscanf(fp, "%63s %ld kB\n", l, &v) == 2)
            {
                if (!strcmp(l, "MemTotal:"))
                    mt = v;
                if (!strcmp(l, "MemFree:"))
                    mf = v;
                if (!strcmp(l, "Buffers:"))
                    mb = v;
                if (!strcmp(l, "Cached:"))
                    mc = v;
            }
            fclose(fp);
        }
        double mem_pct = mt ? (double)(mt - mf - mb - mc) / mt * 100.0 : 0;
        double l1 = 0;
        fp = fopen("/proc/loadavg", "r");
        if (fp)
        {
            fscanf(fp, "%lf", &l1);
            fclose(fp);
        }
        char ts[64];
        get_timestamp(ts, sizeof(ts));
        printf("  [Snapshot %d/5 — %s]\n", i, ts);
        printf("  CPU    : ");
        print_bar(cpu_pct, 35);
        printf("\n");
        printf("  Memory : ");
        print_bar(mem_pct, 35);
        printf("\n");
        printf("  Load1m : %.2f\n\n", l1);
        char buf[128];
        snprintf(buf, sizeof(buf), "Snapshot %d CPU:%.1f%% MEM:%.1f%% LOAD:%.2f",
                 i, cpu_pct, mem_pct, l1);
        write_log(LOG_FILE, "MONITOR", buf);
        intelligent_alert("CPU", cpu_pct, ALERT_CPU_WARN, ALERT_CPU_CRIT, ALERT_CPU_EMER);
        intelligent_alert("Memory", mem_pct, ALERT_MEM_WARN, ALERT_MEM_CRIT, ALERT_MEM_EMER);
    }
    printf(GREEN "  Complete. Logged to: %s\n" RESET, LOG_FILE);
}

void show_alert_log()
{
    print_section("ALERT & EVENT LOG", RED);

    const char *logs[] = {LOG_FILE, CORE_LOG_FILE, PROC_LOG_FILE, NULL};
    const char *names[] = {"Main Alert Log", "Per-Core Log", "Process Log", NULL};

    for (int i = 0; logs[i] != NULL; i++)
    {
        printf("\n  " BOLD "── %s (%s) ──\n" RESET, names[i], logs[i]);
        FILE *fp = fopen(logs[i], "r");
        if (!fp)
        {
            printf("  (no entries yet)\n");
            continue;
        }
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), fp))
        {
            /* Color by severity */
            if (strstr(line, "EMERGENCY"))
                printf(BG_RED BOLD "  %s" RESET, line);
            else if (strstr(line, "CRITICAL"))
                printf(RED "  %s" RESET, line);
            else if (strstr(line, "WARNING"))
                printf(YELLOW "  %s" RESET, line);
            else
                printf("  %s", line);
            count++;
        }
        fclose(fp);
        printf("  Entries: %d\n", count);
    }
}

void export_snapshot()
{
    char fname[128];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(fname, sizeof(fname), "/tmp/sys_snapshot_%Y%m%d_%H%M%S.txt", tm_info);
    FILE *orig = stdout;
    stdout = fopen(fname, "w");
    if (!stdout)
    {
        stdout = orig;
        printf("  Export failed!\n");
        return;
    }
    fprintf(stdout, "=== SYSTEM SNAPSHOT ===\n\n");
    show_cpu_details();
    show_uptime();
    show_loadavg();
    show_memory();
    show_process_stats();
    show_top_processes();
    show_network();
    show_disk();
    show_fd_info();
    show_battery();
    fclose(stdout);
    stdout = orig;
    printf(GREEN "\n  ✔  Snapshot saved: %s\n" RESET, fname);
    write_log(LOG_FILE, "SNAPSHOT", fname);
}

void print_menu()
{
    print_banner();
    printf(BOLD "\n");
    printf("  ┌─────────────────────────────────────────────────────────────┐\n");
    printf("  │  " CYAN " 1." RESET BOLD "  CPU Details + Events                           " BOLD "│\n");
    printf("  │  " CYAN " 2." RESET BOLD "  Per-Core Performance Tracking + Logging        " BOLD "│\n");
    printf("  │  " CYAN " 3." RESET BOLD "  Per-Process Resource Tracking (CPU pct + MEM pct) " BOLD "│\n");
    printf("  │  " CYAN " 4." RESET BOLD "  System Uptime                                  " BOLD "│\n");
    printf("  │  " CYAN " 5." RESET BOLD "  Load Average                                   " BOLD "│\n");
    printf("  │  " CYAN " 6." RESET BOLD "  Memory + Intelligent 3-Level Alerts            " BOLD "│\n");
    printf("  │  " CYAN " 7." RESET BOLD "  Process Analysis (All States)                  " BOLD "│\n");
    printf("  │  " CYAN " 8." RESET BOLD "  Top Processes by Memory & CPU                  " BOLD "│\n");
    printf("  │  " CYAN " 9." RESET BOLD "  Network Interfaces + TCP States                " BOLD "│\n");
    printf("  │  " CYAN "10." RESET BOLD "  Disk Usage + I/O Statistics                    " BOLD "│\n");
    printf("  │  " CYAN "11." RESET BOLD "  File Descriptors & Kernel Limits               " BOLD "│\n");
    printf("  │  " YELLOW "12." RESET BOLD "  Battery Usage Monitoring                      " BOLD "│\n");
    printf("  │  " CYAN "13." RESET BOLD "  Real-Time Monitor (5 snapshots × 2s)           " BOLD "│\n");
    printf("  │  " CYAN "14." RESET BOLD "  View All Alert & Event Logs                    " BOLD "│\n");
    printf("  │  " CYAN "15." RESET BOLD "  Export Full Snapshot to File                   " BOLD "│\n");
    printf("  │  " GREEN "16." RESET BOLD "  Show ALL Information                          " BOLD "│\n");
    printf("  │  " RED " 0." RESET BOLD "  Exit                                            " BOLD "│\n");
    printf("  └─────────────────────────────────────────────────────────────┘\n");
    printf(RESET);
    printf(CYAN "\n  Alert Logs: %s\n" RESET, LOG_FILE);
}

int main()
{
    int choice;
    write_log(LOG_FILE, "SESSION", "Analyzer started");

    while (1)
    {
        system("clear");
        print_menu();
        printf(BOLD "\n  Enter choice: " RESET);
        scanf("%d", &choice);
        getchar();
        system("clear");
        print_banner();

        switch (choice)
        {
        case 1:
            show_cpu_details();
            break;
        case 2:
            show_percore_tracking();
            break;
        case 3:
            show_process_resource_tracking();
            break;
        case 4:
            show_uptime();
            break;
        case 5:
            show_loadavg();
            break;
        case 6:
            show_memory();
            break;
        case 7:
            show_process_stats();
            break;
        case 8:
            show_top_processes();
            break;
        case 9:
            show_network();
            break;
        case 10:
            show_disk();
            break;
        case 11:
            show_fd_info();
            break;
        case 12:
            show_battery();
            break;
        case 13:
            realtime_monitor();
            break;
        case 14:
            show_alert_log();
            break;
        case 15:
            export_snapshot();
            break;
        case 16:
            show_cpu_details();
            show_percore_tracking();
            show_process_resource_tracking();
            show_uptime();
            show_loadavg();
            show_memory();
            show_process_stats();
            show_top_processes();
            show_network();
            show_disk();
            show_fd_info();
            show_battery();
            break;
        case 0:
            write_log(LOG_FILE, "SESSION", "Analyzer exited");
            printf(GREEN "\n  Goodbye!\n" RESET);
            exit(0);
        default:
            printf(RED "  Invalid choice.\n" RESET);
        }
        printf(BOLD "\n\n  Press ENTER to return to menu..." RESET);
        getchar();
    }
    return 0;
}