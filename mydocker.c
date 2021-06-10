#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <regex.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RUNTIME_DIR "/mnt/mydocker/"
#define CONTAINER_DIR RUNTIME_DIR "containers/"
#define MERGED_DIR "merged/"
#define WORK_DIR "work/"
#define UPPER_DIR "upper/"

static size_t STACK_SIZE = 65536;
static const char chars[] = {"abcdefghijklmnopqrstuvwxyz0123456789"};

typedef struct user_volume {
    char *host_dir;
    char *dest_dir;
    char *mount_options;
} user_volume_t;

typedef struct {
    char *name;
    const char *image;
    char *container_dir;
    char *upper_dir;
    const char **lower_dir;
    char *merged_dir;
    char *work_dir;
    char *id;
    char **run_args;
    pid_t pid;
    bool tty;
    bool interactive;
    int *sync_pipe;
    user_volume_t **user_volumes;
} container_t;

void release_container_t(container_t *c)
{
    if (c == NULL)
        return;
    if (c->name != NULL)
        free(c->name);
    if (c->id != NULL)
        free(c->id);
    if (c->run_args != NULL)
        free(c->run_args);
    if (c->sync_pipe)
        free(c->sync_pipe);
    if (c->container_dir)
        free(c->container_dir);
    if (c->upper_dir)
        free(c->upper_dir);
    if (c->merged_dir)
        free(c->merged_dir);
    if (c->work_dir)
        free(c->work_dir);
    if (c->user_volumes) {
        for (user_volume_t **tmp = c->user_volumes; *tmp != NULL; tmp++) {
            if ((*tmp)->host_dir)
                free((*tmp)->host_dir);
            if ((*tmp)->dest_dir)
                free((*tmp)->dest_dir);
            if ((*tmp)->mount_options)
                free((*tmp)->mount_options);
            free(*tmp);
        }
        free(c->user_volumes);
    }
    free(c);
}

static inline void init_random() { srandom(time(NULL)); }

char *random_str(size_t len, const char *characters)
{
    char *str = malloc(sizeof(char) * len + 1);
    if (str == NULL) {
        dprintf(STDERR_FILENO, "line %d: malloc error: %s\n", __LINE__,
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    char *tmp = str;
    size_t chars_len = strlen(characters);
    for (int i = 0; i < len; i++, tmp++) {
        *tmp = characters[random() % chars_len];
    }
    *tmp = '\0';

    return str;
}

char **copy_run_args(int argc, char **argv)
{
    if (optind < argc) {
        int args_num = argc - optind;
        char **run_args = malloc(sizeof(void *) * args_num + 1);
        char **tmp = run_args;
        if (run_args == NULL) {
            dprintf(STDERR_FILENO, "line %d: malloc error: %s\n", __LINE__,
                    strerror(errno));
            exit(EXIT_FAILURE);
        }
        for (; optind < argc; optind++, tmp++) {
            *tmp = argv[optind];
        }
        *tmp = NULL;
        return run_args;
    }
    else
        return NULL;
}

bool dir_exist(const char *file_path)
{
    if (file_path == NULL)
        return false;

    struct stat stat_info;
    if (stat(file_path, &stat_info) == -1) {
        dprintf(STDERR_FILENO, "line %d: dir_exist: %s\n", __LINE__,
                strerror(errno));
        return false;
    }
    return ((stat_info.st_mode & S_IFMT) == S_IFDIR) ? true : false;
}

int mkdir_recursive(const char *dir)
{
    int ret = -1;
    struct stat info;
    if (stat(dir, &info) == 0 && S_ISDIR(info.st_mode))
        return 0;

    char *tmp = malloc(strlen(dir) + 1);
    if (tmp == NULL) {
        dprintf(STDERR_FILENO, "[%d] malloc() failed: %s\n", __LINE__,
                strerror(errno));
        return ret;
    }
    strcpy(tmp, dir);

    for (char *token = strchr(tmp + 1, '/'); token != NULL;
         token = strchr(token + 1, '/')) {
        char orig = *token;
        *token = '\0';
        if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
            dprintf(STDERR_FILENO, "[%d] failed to mkdir %s: %s\n", __LINE__,
                    tmp, strerror(errno));
            goto out;
        }
        *token = orig;
    }
    if (mkdir(tmp, 0700) == -1) {
        dprintf(STDERR_FILENO, "[%d] failed to mkdir %s: %s\n", __LINE__, tmp,
                strerror(errno));
        goto out;
    }
    ret = 0;

out:
    free(tmp);
    return ret;
}

int child_func(void *arg)
{
    container_t *c = (container_t *)arg;
    char dummy[1];

    close(c->sync_pipe[1]);

    char dest_dir[PATH_MAX];
    if (c->user_volumes) {
        for (user_volume_t **tmp = c->user_volumes; tmp != NULL && *tmp != NULL;
             tmp++) {
            strncat(dest_dir, c->merged_dir, PATH_MAX - 1);
            strncpy(dest_dir + strlen(c->merged_dir) - 1, (*tmp)->dest_dir,
                    PATH_MAX - strlen(c->merged_dir));
            if (mkdir_recursive(dest_dir) == -1)
                return -1;
            if (mount((*tmp)->host_dir, dest_dir, "bind", MS_BIND | MS_REC,
                      "") == -1) {
                dprintf(
                    STDERR_FILENO,
                    "[%d] failed to mount %s to %s as MS_BIND | MS_REC: %s\n",
                    __LINE__, (*tmp)->host_dir, dest_dir, strerror(errno));
                return 1;
            }
            if (mount("", dest_dir, "", MS_PRIVATE | MS_REC, "") == -1) {
                dprintf(STDERR_FILENO,
                        "[%d] failed to mount %s to %s as MS_PRIVATE | MS_REC: "
                        "%s\n",
                        __LINE__, (*tmp)->host_dir, dest_dir, strerror(errno));
                return 1;
            }
            int mount_options = MS_BIND | MS_REC | MS_REMOUNT;
            if (strcmp((*tmp)->mount_options, "ro") == 0)
                mount_options |= MS_RDONLY;
            if (mount((*tmp)->host_dir, dest_dir, "bind", mount_options, "") ==
                -1) {
                dprintf(STDERR_FILENO,
                        "[%d] failed to mount %s to %s: "
                        "%s\n",
                        __LINE__, (*tmp)->host_dir, dest_dir, strerror(errno));
                return 1;
            }
        }
    }

    if (mount("", "/", NULL, MS_REC | MS_SLAVE, NULL) == -1) {
        dprintf(STDERR_FILENO, "[%d] mount --make-rslave: %s\n", __LINE__,
                strerror(errno));
        return 1;
    }
    if (mount(c->merged_dir, c->merged_dir, "bind", MS_BIND | MS_REC, NULL) ==
        -1) {
        dprintf(STDERR_FILENO, "[%d] mount --make-rprivate: %s\n", __LINE__,
                strerror(errno));
        return 1;
    }
    if (chdir(c->merged_dir) == -1) {
        dprintf(STDERR_FILENO, "[%d] failed to chdir to %s: %s\n", __LINE__,
                c->merged_dir, strerror(errno));
        return 1;
    }
    if (syscall(SYS_pivot_root, ".", ".") == -1) {
        dprintf(STDERR_FILENO, "[%d] pivot_root %s %s: %s\n", __LINE__,
                c->merged_dir, c->merged_dir, strerror(errno));
        return 1;
    }
    if (chdir("/") == -1) {
        dprintf(STDERR_FILENO, "[%d] failed to chdir to %s: %s\n", __LINE__,
                "/", strerror(errno));
        return 1;
    }
    if (umount2(".", MNT_DETACH) == -1) {
        dprintf(STDERR_FILENO, "[%d] failed to detach old fs: %s\n", __LINE__,
                strerror(errno));
        return 1;
    }
    if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
        dprintf(STDERR_FILENO, "[%d] failed to mount proc: %s\n", __LINE__,
                strerror(errno));
        return 1;
    }

    if (read(c->sync_pipe[0], dummy, 1) == -1) {
        dprintf(STDERR_FILENO, "line %d: read pipe error: %s\n", __LINE__,
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    close(c->sync_pipe[0]);

    if (execve(c->run_args[0], c->run_args, NULL) == -1) {
        dprintf(STDERR_FILENO, "line %d: execve error: %s\n", __LINE__,
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    return 0;
}

int run_container(container_t *c)
{
    char *stack = malloc(STACK_SIZE);
    if (stack == NULL) {
        dprintf(STDERR_FILENO, "line %d: malloc error: %s\n", __LINE__,
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    char *stack_top = stack + STACK_SIZE;
    pid_t pid = clone(child_func, stack_top,
                      CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID |
                          CLONE_NEWUTS,
                      (void *)c);

    free(stack);
    return pid;
}

int set_container_name(container_t *c, const char *name)
{
    /* generate a unique container ID */
    char *id = random_str(64, chars);
    c->id = id;
    /* set container name */
    char *container_name;
    if (name == NULL || strcmp(name, "") == 0) {
        container_name = strdup(id);
        if (container_name == NULL) {
            dprintf(STDERR_FILENO, "line %d: strdup error: %s\n", __LINE__,
                    strerror(errno));
            return -1;
        }
    }
    else {
        container_name = strdup(name);
        if (container_name == NULL) {
            dprintf(STDERR_FILENO, "line %d: strdup error: %s\n", __LINE__,
                    strerror(errno));
            return -1;
        }
    }
    c->name = container_name;

    return 0;
}
int *create_pipe()
{
    int *pip = malloc(sizeof(int) * 2);
    if (pip == NULL) {
        dprintf(STDERR_FILENO, "line %d: malloc error: %s\n", __LINE__,
                strerror(errno));
        return NULL;
    }
    if (pipe(pip) == -1) {
        dprintf(STDERR_FILENO, "line %d: pipe error: %s\n", __LINE__,
                strerror(errno));
        return NULL;
    }

    return pip;
}

int prepare_dirs(container_t *c)
{
    int ret = -1;
    unsigned long container_dir_len = strlen(CONTAINER_DIR) + strlen(c->id) + 2;
    char *container_dir = malloc(container_dir_len);
    if (container_dir == NULL) {
        dprintf(STDERR_FILENO, "[%d] malloc() failed: %s\n", __LINE__,
                strerror(errno));
        return ret;
    }
    snprintf(container_dir, container_dir_len, "%s%s/", CONTAINER_DIR, c->id);
    c->container_dir = container_dir;
    if (mkdir(container_dir, 0700) == -1) {
        dprintf(STDERR_FILENO,
                "[%d] failed to create container directory %s: %s\n", __LINE__,
                container_dir, strerror(errno));
        return ret;
    }

    unsigned long merged_dir_len =
        strlen(container_dir) + strlen(MERGED_DIR) + 1;
    char *merged_dir = malloc(merged_dir_len);
    if (merged_dir == NULL) {
        dprintf(STDERR_FILENO, "[%d] malloc() failed: %s\n", __LINE__,
                strerror(errno));
        return ret;
    }
    c->merged_dir = merged_dir;
    snprintf(merged_dir, merged_dir_len, "%s%s", container_dir, MERGED_DIR);
    if (mkdir(merged_dir, 0700) == -1) {
        dprintf(STDERR_FILENO,
                "[%d] failed to create merged directory %s: %s\n", __LINE__,
                merged_dir, strerror(errno));
        return ret;
    }

    unsigned long work_dir_len = strlen(container_dir) + strlen(WORK_DIR) + 1;
    char *work_dir = malloc(work_dir_len);
    if (work_dir == NULL) {
        dprintf(STDERR_FILENO, "[%d] malloc() failed: %s\n", __LINE__,
                strerror(errno));
        return ret;
    }
    c->work_dir = work_dir;
    snprintf(work_dir, work_dir_len, "%s%s", container_dir, WORK_DIR);
    if (mkdir(work_dir, 0700) == -1) {
        dprintf(STDERR_FILENO,
                "[%d] failed to create merged directory %s: %s\n", __LINE__,
                merged_dir, strerror(errno));
        return ret;
    }

    unsigned long upper_dir_len = strlen(container_dir) + strlen(UPPER_DIR) + 1;
    char *upper_dir = malloc(upper_dir_len);
    if (upper_dir == NULL) {
        dprintf(STDERR_FILENO, "[%d] malloc() failed: %s\n", __LINE__,
                strerror(errno));
        return ret;
    }
    c->upper_dir = upper_dir;
    snprintf(upper_dir, upper_dir_len, "%s%s", container_dir, UPPER_DIR);
    if (mkdir(upper_dir, 0700) == -1) {
        dprintf(STDERR_FILENO, "[%d] failed to create upper directory %s: %s\n",
                __LINE__, merged_dir, strerror(errno));
        return ret;
    }

    unsigned long mount_options_len =
        strlen(c->image) + strlen(work_dir) + strlen(upper_dir) + 29;
    for (const char **tmp = c->lower_dir; tmp != NULL && *tmp != NULL; tmp++)
        mount_options_len += strlen(*tmp) + 1;
    mount_options_len--;
    char *mount_options = malloc(mount_options_len);
    if (mount_options == NULL) {
        dprintf(STDERR_FILENO, "[%d] malloc() failed: %s\n", __LINE__,
                strerror(errno));
        return ret;
    }
    const char *lower = "lowerdir=";
    const char *upper = "upperdir=";
    const char *work = "workdir=";
    size_t cursor = 0;
    strncpy(mount_options + cursor, lower, strlen(lower));
    cursor += strlen(lower);
    strncpy(mount_options + cursor, c->image, strlen(c->image));
    cursor += strlen(c->image);
    for (const char **tmp = c->lower_dir; tmp != NULL && *tmp != NULL; tmp++) {
        strncpy(mount_options + cursor, *tmp, strlen(*tmp));
        cursor += strlen(*tmp);
        strncpy(mount_options + cursor, ":", 1);
        cursor++;
    }
    mount_options[cursor] = ',';
    cursor++;
    strncpy(mount_options + cursor, upper, strlen(upper));
    cursor += strlen(upper);
    strncpy(mount_options + cursor, upper_dir, strlen(upper_dir));
    cursor += strlen(upper_dir);
    mount_options[cursor] = ',';
    cursor++;
    strncpy(mount_options + cursor, work, strlen(work));
    cursor += strlen(work);
    strncpy(mount_options + cursor, work_dir, strlen(work_dir));
    cursor += strlen(work_dir);

    if ((ret = mount("overlay", merged_dir, "overlay", 0, mount_options)) ==
        -1) {
        dprintf(STDERR_FILENO, "[%d] mount -t overlay -o %s %s: %s\n", __LINE__,
                mount_options, merged_dir, strerror(errno));
        goto out;
    }
    ret = 0;

out:
    free(mount_options);
    return ret;
}

container_t *init_container(int argc, char **argv, const char *name,
                            const char *image, bool tty_flag,
                            bool interactive_flag, user_volume_t **volumes)
{
    int ret;
    container_t *c = malloc(sizeof(container_t));
    if (c == NULL) {
        dprintf(STDERR_FILENO, "line %d: malloc error: %s\n", __LINE__,
                strerror(errno));
        return NULL;
    }
    memset(c, 0, sizeof(container_t));

    c->run_args = copy_run_args(argc, argv);
    if (c->run_args == NULL) {
        dprintf(STDERR_FILENO,
                "wrong usage. Please specify a program to run\n");
        goto out;
    }

    if (set_container_name(c, name) != 0)
        goto out;

    if (tty_flag == true)
        c->tty = true;
    if (interactive_flag == true)
        c->interactive = true;
    if (image != NULL)
        c->image = image;
    else {
        fprintf(stderr, "Please specify an image to run\n");
        goto out;
    }
    c->user_volumes = volumes;

    c->sync_pipe = create_pipe();
    if (c->sync_pipe == NULL)
        goto out;

    prepare_dirs(c);
    return c;

out:
    release_container_t(c);
    return NULL;
}

int action_run(container_t *c)
{
    pid_t child_pid = run_container(c);
    if (child_pid == -1) {
        dprintf(STDERR_FILENO, "line %d: clone error: %s\n", __LINE__,
                strerror(errno));
        return 1;
    }
    else
        c->pid = child_pid;

    dprintf(STDOUT_FILENO, "%s\n", c->id);

    close(c->sync_pipe[0]);
    close(c->sync_pipe[1]);
    /* wait container finish */
    int exit_code;
    if (waitpid(-1, &exit_code, __WALL) == -1) {
        dprintf(STDERR_FILENO, "line %d: waitpid error: %s\n", __LINE__,
                strerror(errno));
    }
    else
        c->pid = exit_code;

    if (umount2(c->merged_dir, MNT_DETACH) == -1) {
        dprintf(STDERR_FILENO, "[%d] failed to umount %s: %s\n", __LINE__,
                c->merged_dir, strerror(errno));
        return -1;
    }

    return 0;
}

user_volume_t *parse_volume_options(const char *value)
{
    regex_t regex;
    user_volume_t *volume = NULL;
    int max_groups = 4;
    regmatch_t group_array[max_groups];
    if (regcomp(&regex, "^([^:]+):([^:]+)(:rw|:ro)?$", REG_EXTENDED) != 0) {
        dprintf(STDERR_FILENO, "[%d] invalid regular expression\n", __LINE__);
        return volume;
    }

    volume = (user_volume_t *)malloc(sizeof(user_volume_t));
    if (volume == NULL) {
        dprintf(STDERR_FILENO, "[%d] malloc() error: %s\n", __LINE__,
                strerror(errno));
        return volume;
    }
    memset(volume, 0, sizeof(user_volume_t));

    if (regexec(&regex, value, max_groups, group_array, 0) == 0) {
        for (int i = 0; i < max_groups; i++) {
            if (group_array[i].rm_so == -1)
                break;
            if (i == 0)
                continue;

            size_t length = group_array[i].rm_eo - group_array[i].rm_so + 1;
            char *tmp = malloc(length);
            if (tmp == NULL) {
                dprintf(STDERR_FILENO, "[%d] malloc() failed: %s\n", __LINE__,
                        strerror(errno));
                return volume;
            }
            strncpy(tmp, value + group_array[i].rm_so, length - 1);
            tmp[length - 1] = '\0';
            switch (i) {
            case 1:
                volume->host_dir = tmp;
                break;
            case 2:
                volume->dest_dir = tmp;
                break;
            case 3:
                volume->mount_options = tmp + 1;
                break;
            }
        }
    }
    else {
        dprintf(STDERR_FILENO, "invalid user volumes: %s\n", value);
    }

    return volume;
}

int main(int argc, char *argv[])
{
    int ch, ret;
    int option_index = 0;
    bool run_flag = false;
    bool interactive_flag = false;
    bool terminal_flag = false;
    bool tty_flag = false;
    const char *action = NULL;
    const char *name = NULL;
    const char *image = NULL;
    user_volume_t **volumes = NULL;
    int volumes_num = 0;
    struct option long_options[] = {
        {"action", required_argument, 0, 0},
        {"run", required_argument, (int *)&run_flag, true},
        {"name", required_argument, 0, 0},
        {"interactive", required_argument, (int *)&interactive_flag, true},
        {"terminal", required_argument, (int *)&terminal_flag, true},
        {"tty", required_argument, (int *)&tty_flag, true},
        {"image", required_argument, 0, 0},
        {"volume", required_argument, 0, 0},
        {0, 0, 0, 0},
    };

    init_random();

    while ((ch = getopt_long(argc, argv, "", long_options, &option_index)) !=
           -1) {
        switch (ch) {
        case 0: {
            if (strcmp(long_options[option_index].name, "action") == 0) {
                action = optarg;
            }
            else if (strcmp(long_options[option_index].name, "name") == 0) {
                name = optarg;
            }
            else if (strcmp(long_options[option_index].name, "image") == 0)
                image = optarg;
            else if (strcmp(long_options[option_index].name, "volume") == 0) {
                volumes_num++;
                volumes = realloc(volumes, sizeof(void *) * (volumes_num + 1));
                if (volumes == NULL) {
                    dprintf(STDERR_FILENO, "malloc() error: %s\n",
                            strerror(errno));
                    return 1;
                }
                *(volumes + volumes_num - 1) = parse_volume_options(optarg);
                *(volumes + volumes_num) = NULL;
            }
            break;
        }
        case '?':
        default:
            exit(EXIT_FAILURE);
        }
    }

    if (action == NULL) {
        dprintf(STDERR_FILENO, "wrong usage. Please specify action\n");
        exit(EXIT_FAILURE);
    }
    container_t *c = init_container(argc, argv, name, image, tty_flag,
                                    interactive_flag, volumes);
    if (c == NULL) {
        release_container_t(c);
        return 1;
    }
    if (strcmp(action, "run") == 0) {
        action_run(c);
    }

    return 0;
}
