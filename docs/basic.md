# Basic

TODO:

- [ ] 完善文档

- [ ] 搞清楚 `waitpid(2)` 中 `__WALL`、`__WCLONE` 标志的问题

- [ ] `clone(2)` 内核源码的简单分析

- [ ] 命名空间相关内核源码的简单分析

## 目标

在这一部分，我们将使用 `clone(2)` 系统调用实现一个最简单的 Docker。运行结果为：

```
➜  mydocker-c git:(master) ✗ gcc -g -o mydocker mydocker.c
➜  mydocker-c git:(master) ✗ sudo ./mydocker --action run --name -- /bin/sh
sykiaqo46517580be20aq47z4yrfefocjzlzvf97a0l5ybm2jcjfmgkgli25nw7c
sh-5.1# ip link
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
sh-5.1# hostname
nitrocao
sh-5.1# hostname Linux
sh-5.1# hostname
Linux
sh-5.1# exit
exit
```

## 实现步骤

父进程的处理流程（主要逻辑在 `action_run` 函数中）：

* 父进程使用标准库的 `getopt(3)` 函数解析命令行参数。
* 获取要在容器中运行的命令以及其参数。（`copy_run_args` 函数）
* 生成一个常为 `64` 位的随机字符串作为容器的 ID。如果命令行参数没有指定名称，则使用容器 ID 作为名称。（`set_container_name` 函数）
* 创建一个管道用于父子进程间的同步。（`create_pipe` 函数）
* 父进程调用 `clone(2)` 系统调用创建子进程，并获取子进程的 PID。（`run_container` 函数）
* 父进程执行必须在子进程创建后才能进行的配置步骤。
* 父进程关闭管道的读端和写端，表示设置完成，子进程继续执行。
* 父进程调用 `waitpid(2)` 系统调用等待子进程的结束，并获取子进程的退出码。
* 父进程进行必要的资源释放。（`release_container_t` 函数）

子进程的处理流程（主要逻辑在 `child_func` 函数中）：

* 关闭管道的写端，并调用 `read(2)` 系统调用读管道，以等待父进程完成配置工作。
* 关闭管道的读端。
* 调用 `execve(2)` 系统调用加载要执行的程序。

## 关键知识

### clone(2)

一般情况下，在 Linux 下通过 `fork(2)` 系统调用创建一个新的进程，调用 `fork(2)` 的进程叫做父进程，新创建的进程叫做父进程的一个子进程。子进程完全复制于父进程，只是采用了写时复制（COW，Copy-on-write）技术，即当父进程或子进程要对任意内存区域作修改时，内核会先为对应的内存区域创建一份拷贝，然后进程在新创建的拷贝上进行操作。  两个进程从 `fork(2)` 的返回处继续执行。

`clone(2)` 也用来创建一个新的进程，只是对创建过程控制得更精细。一般情况下 `clone(2)` 系统调用用来实现用户态的线程库。调用成功时 `clone()` 返回子进程的 PID，失败时返回 -1 并设置 errno 的值。  

我们的代码中调用 `clone()` 时指定的 `flags` 参数为：`CLONE_NEWNS |CLONE_NEWPID | CLONE_NEWUTS |CLONE_NEWNET | CLONE_NEWIPC`。作用分别为：

* `CLONE_NEWNS`：子进程创建一个新的 mount 命名空间，并继承父进程的副本。
* `CLONE_NEWPID`：子进程创建一个新的 PID 命名空间。
* `CLONE_NEWUTS`：子进程创建一个新的 UTS 命名空间，并进程父进程的副本。
* `CLONE_NEWNET`：子进程创建一个新的网络命名空间。
* `CLONE_NEWIPC`：子进程创建一个新的 System V IPC 命名空间。IPC 即进程间通信。

我们通过 `clone()` 的第四个参数将 `container_t` 结构体指针传递给子进程。

### waitpid(2)

《Linux/UNIX 系统编程手册》中指出，为 clone 生成的子进程对 `waitpid(2)` 进行了扩展，添加了三个位掩码标志，`__WALL`、`__WCLONE` 以及 `__WNOTHREAD`。使用 `__WALL` 时一切正常，使用 `__WCLONE` 时，在子进程退出之后，waitpid 会报 `ECHILD` 错误。
