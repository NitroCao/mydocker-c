#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <getopt.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static size_t STACK_SIZE = 65536;
static const char chars[] = {"abcdefghijklmnopqrstuvwxyz0123456789"};

typedef struct {
    char *name;
    char *id;
    char **run_args;
    pid_t pid;
    bool tty;
    bool interactive;
    int *sync_pipe;
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

int child_func(void *arg)
{
    container_t *c = (container_t *)arg;
    char dummy[1];

    close(c->sync_pipe[1]);
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

int action_run(int argc, char **argv, const char *name, bool tty_flag,
               bool interactive_flag)
{
    int ret;
    container_t *c = malloc(sizeof(container_t));
    if (c == NULL) {
        dprintf(STDERR_FILENO, "line %d: malloc error: %s\n", __LINE__,
                strerror(errno));
        return 1;
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

    c->sync_pipe = create_pipe();
    if (c->sync_pipe == NULL)
        goto out;

    pid_t child_pid = run_container(c);
    if (child_pid == -1) {
        dprintf(STDERR_FILENO, "line %d: clone error: %s\n", __LINE__,
                strerror(errno));
        goto out;
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

    return 0;
out:
    release_container_t(c);
    return 1;
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
    struct option long_options[] = {
        {"action", required_argument, 0, 0},
        {"run", required_argument, (int *)&run_flag, true},
        {"name", required_argument, 0, 0},
        {"interactive", required_argument, (int *)&interactive_flag, true},
        {"terminal", required_argument, (int *)&terminal_flag, true},
        {"tty", required_argument, (int *)&tty_flag, true},
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
    if (strcmp(action, "run") == 0) {
        action_run(argc, argv, name, tty_flag, interactive_flag);
    }

    return 0;
}
