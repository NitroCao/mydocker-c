本文使用的内核版本：`5.11.1`。在线查看源码：[https://elixir.bootlin.com/linux/v5.11.1/source](https://elixir.bootlin.com/linux/v5.11.1/source)。

# Clone() 系统调用的源码分析

本文对 `clone()` 系统调用的源码进行简单的分析。对于每个命名空间，之后涉及到时会详细解释。

本文不会包含太多很容易从书本中找到的内容，文末会给出相关书籍的参考书籍和链接。

## 命名空间种类

内核描述 PCB（Process Control Block）的结构体 `task_struct` 中，与命名空间有关的成员是变量名为 `nsproxy` 的指针，指向类型为定义在 `/include/linux/nsproxy.h` 中的 `struct nsproxy` 结构体实例（https://elixir.bootlin.com/linux/v5.11.1/source/include/linux/nsproxy.h#L31）：

```c
struct task_struct {
...
/* Namespaces: */
	struct nsproxy			*nsproxy;
...
}
```



```c
// /include/linux/nsproxy.h
/*
 * A structure to contain pointers to all per-process
 * namespaces - fs (mount), uts, network, sysvipc, etc.
 *
 * The pid namespace is an exception -- it's accessed using
 * task_active_pid_ns.  The pid namespace here is the
 * namespace that children will use.
 *
 * 'count' is the number of tasks holding a reference.
 * The count for each namespace, then, will be the number
 * of nsproxies pointing to it, not the number of tasks.
 *
 * The nsproxy is shared by tasks which share all namespaces.
 * As soon as a single namespace is cloned or unshared, the
 * nsproxy is copied.
 */
struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};
extern struct nsproxy init_nsproxy;
```

其中每个结构体对应一种命名空间。所以当前 Linux 内核支持的命名空间有：

* `struct uts_namespace`：UTS 命名空间。UTS 即 Unix Time Sharing 的缩写。
* `struct ipc_namespace`：IPC 命名空间。IPC 即 Inter Process Communication 的缩写。
* `struct mnt_namespace`：mount 命名空间。
* `struct pid_namespace`：PID 命名空间。PID 即 Process ID。
* `struct net`：网络命名空间。
* `struct time_namespace`：时间命名空间。
* `struct cgroup_namespace`：cgroup 命名空间。

可以看到内核声明了一个名为 `init_nsproxy` 的外部全局变量，其定义在 `/kernel/nsproxy.c` 中（https://elixir.bootlin.com/linux/v5.11.1/source/kernel/nsproxy.c#L32）。它其实是系统中的初始命名空间，内核在启动时会使用其进行初始化。

## clone() 系统调用的实现

clone 系统调用的定义在 `/kernel/fork.c` 中（https://elixir.bootlin.com/linux/v5.11.1/source/kernel/fork.c#L2563）。可以看到实际工作是由 `kernel_clone()` （https://elixir.bootlin.com/linux/v5.11.1/source/kernel/fork.c#L2421）函数完成。而大部分工作又委托给了 `copy_process()` 函数（https://elixir.bootlin.com/linux/v5.11.1/source/kernel/fork.c#L1844）。`copy_process()` 函数中，与命名空间有关的工作由定义在 `/kernel/nsproxy.c` 中的 `copy_namespaces()` 函数（https://elixir.bootlin.com/linux/v5.11.1/source/kernel/nsproxy.c#L151）完成。因此我们重点关注这个函数。  

注意在 `copy_process()` 中，传递给`copy_namespaces()` 的 `task_struct` 实例是子进程的 PCB，用 `dup_task_struct()` 函数创建的一个父进程的副本。

### copy_namespaces()

`copy_namespaces()` 的原型为：

```c
/*
 * called from clone.  This now handles copy for nsproxy and all
 * namespaces therein.
 */
int copy_namespaces(unsigned long flags, struct task_struct *tsk);
```

从函数调用栈可以知道，`flags` 参数值其实就来自用户态进程执行 `clone()` 系统调用时传入的第三个参数。而 `tsk` 参数指向当前进程的 `task_struct` 结构体指针。

此函数的流程大致为：

* 测试 `flags` 中是否包含了 `CLONE_NEW*` 系列标志位。如果没有包含，则不需要创建新的命名空间，只需增加父进程 `task_struct` 中指向的 `struct nsproxy` 实例的计数。
* 如果包含 `CLONE_NEW*` 系列标志位，则先检查当前进程是否具有创建命名空间的权限，即测试是否具有 `CAP_SYS_ADMIN` 的 capability。如果不具有，则返回 `-EPERM`。
* 测试非法的标志位组合。例如 `CLONE_NEWIPC` 和 `CLONE_SYSVSEM` 不能同时使用。
* 调用 `create_new_namespaces()` （`/kernel/nsproxy.c`，https://elixir.bootlin.com/linux/v5.11.1/source/kernel/nsproxy.c#L67）函数创建新的命名空间。
* 让当前 `task_struct` 实例指向新创建的 `struct nsproxy` 实例，并返回。

### create_new_namespaces()

此函数的原型为：

```c
/*
 * Create new nsproxy and all of its the associated namespaces.
 * Return the newly created nsproxy.  Do not attach this to the task,
 * leave it to the caller to do proper locking and attach it to task.
 */
static struct nsproxy *create_new_namespaces(unsigned long flags,
	struct task_struct *tsk, struct user_namespace *user_ns,
	struct fs_struct *new_fs);
```

每个参数的含义为：

* `flags` 参数含义与 `copy_namespaces()` 中的相同。
* `tsk` 参数含义与 `copy_namespaces()` 中的相同。
* `user_ns` 参数与用户命名空间有关。
* `new_fs` 指向父进程的 `fs_struct` 结构体实例。

此函数的目的很简单，创建一个 `struct nsproxy` 结构实例，以及其内部指向的与具体命名空间相关的结构体实例，然后返回一个指向新创建的这个实例的指针。

此函数依次调用与具体命名空间相关的函数，来创建相应的命名空间结构体实例：

* `copy_mnt_ns()`
* `copy_utsname()`
* `copy_ipcs()`
* `copy_pid_ns()`
* `copy_cgroup_ns()`
* `copy_net_ns()`
* `copy_time_ns()`

## References

* 《深入理解 Linux 内核架构》，第二章第三节（2.3）

