# 配置 qemu + busybox + gdb 调试 Linux 内核的环境

本文简要介绍如何使用 qemu 和 gdb 以及 busybox 来搭建一个最小化的 Linux 调试环境。



## busybox

busybox 包含了常用的一些命令。

下载源码：https://busybox.net/downloads/busybox-1.33.1.tar.bz2

编译安装：

```shell
$ tar -xjf busybox-1.33.1.tar.bz2
$ cd busybox-1.31.1/
$ # 要配置成静态链接。在 Settings 菜单中打开 Build static binary (no shared libs) 选项
$ make menuconfig
$ # 使用 grep 命令确认静态链接选项已经打开
$ grep STATIC .config
CONFIG_STATIC=y
......
$ make -j$(nproc)
$ make install
```

这里有个坑，因为我们是静态编译，所以要求系统里存在所有用到的库的静态链接库。比如我用 ArchLinux 编译时，在最后链接的时候会报错 `/usr/bin/ld: cannot find -lcrypt`。`-lcrypt` 选项其实就是链接 `/usr/lib/libcrypt.a` 这个静态链接库，在 ArchLinux 中这个库是由 OpenSSL 包提供的，但是官方仓库在打包的时候并没有添加生成静态库的选项，所以 ArchLinux 中编译 busybox 就会失败。用 `pkgfile` 命令搜一下 `libcrypto.a` 这个文件有哪些包提供，发现 `archlinuxcn` 源的 `pacman-static` 包有，于是安装这个包，然后找到这个静态库的路径 `/usr/lib/pacman/lib/libcrypto.a`，拷贝到 `/usr/lib` 目录下并重命名为 `libcrypt.a`。再次 make 就完成了。

## initramfs

Linux 内核启动时所必需的初始文件系统。

创建一个目录用于构建 initramfs。

```shell
$ mkdir initramfs && cd initramfs
$ cp ../busybox-1.33.1/_install/* -rf ./
$ mkdir dev proc sys mnt
$ rm linuxrc
$ nvim init
$ chmod a+x init
```

init 文件的内容为：

```bash
#!/bin/busybox sh
mount -t proc none /proc
mount -t sysfs none /sys

/bin/mdev -s
exec /sbin/init
```

然后打包 initramfs：

```shell
$ find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
```

用 qemu 启动内核：

```shell
$ sudo qemu-system-x86_64 -m 1G -s -kernel /home/nitrocao/linux-kernel/linux/arch/x86/boot/bzImage -initrd initramfs.cpio.gz -nographic -append "console=ttyS0 nokaslr" -net nic -net bridge,br=br0 -hda /home/nitrocao/linux-kernel/vhd.img
```

* `-m` 参数指定虚拟机的内存大小。
* `-s` 参数让 qemu 启动 gdb server。
* `-kernel` 指定压缩的内核镜像文件。
* `-initrd` 指定 initramfs 文件。
* `-nographic` 指定我们不需要图形界面。
* `-append` 传递给内核的启动参数。`console=ttyS0` 指定输出控制台设备。`nokaslr` 指定内核不要启用内核地址空间布局随机化。这个参数非常重要，如果不加这个参数，使用 gdb 调试的时候会出问题。
* `-net` 配置网络信息。
* `-hda` 指定一个虚拟硬盘文件。
* `-enable-kvm` 指定启用硬件虚拟化加速。不建议使用这个选项，因为之前遇到过 bug，启用这个选项后，在用 gdb 调试时光标会乱跳。

## virtual disk

使用 dd 命令创建一个虚拟硬盘，并格式化为 `ext4` 文件系统。

```shell
$ sudo dd if=/dev/zero of=./vhd.img BS=1024M count=4
$ sudo mkfs.ext4 ./vhd.img
$ sudo mount -t auto -o loop ./vhd.img /mnt/vhd
```

## strace

strace 用来查看一个程序运行时调用了哪些系统调用，以及具体的调用参数和返回值。

下载源码：https://github.com/strace/strace/releases/download/v5.12/strace-5.12.tar.xz

解压并编译安装：

```shell
$ LDFLAGS="-static -pthread" ./configure --prefix=/mnt/vhd # 把 --prefix 的值修改为自己要安装的位置
$ make -j$(nproc) all
$ file ./src/strace
src/strace: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=ce16f16dcbc0a63e3673fb18f211a36997fab3f4, for GNU/Linux 4.4.0, with debug_info, not stripped
$ # 测试是否正常运行
$ sudo chroot /mnt/vhd /bin/strace --help
Usage: strace [-ACdffhiqqrtttTvVwxxyyzZ] [-I N] [-b execve] [-e EXPR]...
              [-a COLUMN] [-o FILE] [-s STRSIZE] [-X FORMAT] [-O OVERHEAD]
              [-S SORTBY] [-P PATH]... [-p PID]... [-U COLUMNS] [--seccomp-bpf]
              { -p PID | [-DDD] [-E VAR=VAL]... [-u USERNAME] PROG [ARGS] }
......
```

拷贝到 initramfs 或者要挂载到虚拟机的虚拟硬盘中。

## trace-cmd

trace-cmd 用来简化 `ftrace` 的使用。`ftrace` 是内核的一个调试机制，可以观察内核函数的调用栈。

下载源码：https://git.kernel.org/pub/scm/utils/trace-cmd/trace-cmd.git/snapshot/trace-cmd-v2.9.2.tar.gz

解压并编译安装。可以先尝试编译成静态链接文件。如果用到的库没有静态链接库的话编译末期链接的时候会报错。因为我用的 ArchLinux，大多数库没有静态链接库，所以我只能编译成动态链接的文件，然后手动把用到的共享库拷贝到 initramfs 中。

```shell
$ tar -zxf trace-cmd-v2.9.2.tar.gz
$ cd trace-cmd-v2.9.2
$ make prefix=/mnt/vhd -j$(nproc)
$ sudo make prefix=/mnt/vhd -j$(nproc)
$ # 因为我的 ArchLinux 的好多库不支持静态链接，所以需要手动拷贝用到的共享库
$ ldd /mnt/vhd/bin/trace-cmd
        linux-vdso.so.1 (0x00007ffd33fd0000)
        librt.so.1 => /usr/lib/librt.so.1 (0x00007f57bd796000)
        libpthread.so.0 => /usr/lib/libpthread.so.0 (0x00007f57bd775000)
        libtraceevent.so.1 => /usr/lib/libtraceevent.so.1 (0x00007f57bd74f000)
        libtracefs.so.1 => /usr/lib/libtracefs.so.1 (0x00007f57bd743000)
        libdl.so.2 => /usr/lib/libdl.so.2 (0x00007f57bd73c000)
        libaudit.so.1 => /usr/lib/libaudit.so.1 (0x00007f57bd710000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007f57bd542000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f57bd828000)
        libcap-ng.so.0 => /usr/lib/libcap-ng.so.0 (0x00007f57bd53a000)
$ sudo cp /usr/lib/libtraceevent.so.1 ./usr/lib
$ sudo cp /usr/lib/libcap-ng.so.0 ./usr/lib
$ sudo cp /usr/lib64/ld-linux-x86-64.so.2 ./usr/lib64
$ sudo cp /usr/lib/libc.so.6 ./usr/lib
$ sudo cp /usr/lib/libaudit.so.1 ./usr/lib
$ sudo cp /usr/lib/libdl.so.2 ./usr/lib
$ sudo cp /usr/lib/libtracefs.so.1 ./usr/lib
$ sudo cp /usr/lib/libpthread.so.0 ./usr/lib
$ sudo cp /usr/lib/librt.so.1 ./usr/lib
$ # 测试是否能正常运行
$ sudo chroot /mnt/vhd /bin/trace-cmd --help

trace-cmd version 2.9.2 (not-a-git-repo)

usage:
  trace-cmd [COMMAND] ...

  commands:
     record - record a trace into a trace.dat file
     set - set a ftrace configuration parameter
     start - start tracing without recording into a file
     extract - extract a trace from the kernel
     stop - stop the kernel from recording trace data
     restart - restart the kernel trace data recording
     show - show the contents of the kernel tracing buffer
     reset - disable all kernel tracing and clear the trace buffers
     clear - clear the trace buffers
     report - read out the trace stored in a trace.dat file
     stream - Start tracing and read the output directly
     profile - Start profiling and read the output directly
     hist - show a histogram of the trace.dat information
     stat - show the status of the running tracing (ftrace) system
     split - parse a trace.dat file into smaller file(s)
     options - list the plugin options available for trace-cmd report
     listen - listen on a network socket for trace clients
     agent - listen on a vsocket for trace clients
     setup-guest - create FIFOs for tracing guest VMs
     list - list the available events, plugins or options
     restore - restore a crashed record
     snapshot - take snapshot of running trace
     stack - output, enable or disable kernel stack tracing
     check-events - parse trace event formats
     dump - read out the meta data from a trace file
```

## network

配置 qemu 启动的虚拟机的网络。

* 首先创建一个桥接网口。如果已经有的话则不需要创建。

```shell
$ # 创建一个桥接网口
$ sudo ip link add virbr0 type bridge
$ ip link show virbr0
124: virbr0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether e2:44:e7:2f:20:12 brd ff:ff:ff:ff:ff:ff
$ # 为这个网口配置 IP 地址，地址末尾跟上 CIDR
$ sudo ip addr add 192.168.122.1/24 dev virbr0
$ # 启用这个网口
$ sudo ip link set virbr0 up
$ ip addr show virbr0
124: virbr0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether e2:44:e7:2f:20:12 brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.1/24 scope global virbr0
       valid_lft forever preferred_lft forever
$ # 配置 iptables 实现 NAT
$ sudo iptables -t nat -A POSTROUTING -s 192.168.122.0/24 -d 0.0.0.0/0 ! -o virbr0 -j MASQUERADE
$ # 查看 iptables 的 filter 表的 FORWARD 的链的默认动作是否为 ACCEPT，如果不是，修改为 ACCEPT。或者像 docker0 那样，创建两条规则实现转发也行。Chain FORWARD 后括号里，policy 后的值即为当前 chain 的默认规则
$ sudo iptables -t filter -nvL FORWARD --line-numbers
Chain FORWARD (policy ACCEPT 36 packets, 2158 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1    2349K  517M cali-FORWARD  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* cali:wUHhoiAYhphO9Mso */
2    4304K  658M KUBE-FORWARD  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes forwarding rules */
3    3443K  181M KUBE-SERVICES  all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate NEW /* kubernetes service portals */
4    3446K  182M DOCKER-USER  all  --  *      *       0.0.0.0/0            0.0.0.0/0
5    3446K  182M DOCKER-ISOLATION-STAGE-1  all  --  *      *       0.0.0.0/0            0.0.0.0/0
6        0     0 ACCEPT     all  --  *      docker0  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
7        0     0 DOCKER     all  --  *      docker0  0.0.0.0/0            0.0.0.0/0
8        0     0 ACCEPT     all  --  docker0 !docker0  0.0.0.0/0            0.0.0.0/0
9        0     0 ACCEPT     all  --  docker0 docker0  0.0.0.0/0            0.0.0.0/0
10       0     0 ACCEPT     all  --  *      mydocker0  0.0.0.0/0            0.0.0.0/0
11       3   252 ACCEPT     all  --  mydocker0 !mydocker0  0.0.0.0/0            0.0.0.0/0
12       0     0 ACCEPT     all  --  mydocker0 mydocker0  0.0.0.0/0            0.0.0.0/0
13       0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* cali:S93hcgKJrXEqnTfs */ /* Policy explicitly accepted packet. */ mark match 0x10000/0x10000
$ # 当 filter 表的 FORWARD 链的 policy 不为 ACCEPT 时，执行下面的命令将其改为 ACCEPT
$ sudo iptables -t filter -P FORWARD ACCEPT
```

* 使用 `qemu` 启动内核时，指定命令行参数 `-net nic -net bridge,br=virbr0`。把 `br` 的值改为自己对应的桥接网口名称。
* 进入虚拟机后配置 IP 地址。

```shell
/ # # 网口名称为 eth0
/ # ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop qlen 1000
    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
3: sit0@NONE: <NOARP> mtu 1480 qdisc noop qlen 1000
    link/sit 0.0.0.0 brd 0.0.0.0
/ # # 给 eth0 添加 IP 地址
/ # ip addr add 192.168.122.2/24 dev eth0
/ # # 启用 eth0
/ # ip link set eth0 up
/ # # 配置 eth0 网口的默认网关
/ # ip route add default via 192.168.122.1 dev eth0
/ # # 第二条路由在添加完 IP 地址并启用网口后，会由内核自动创建
/ # ip route
default via 192.168.122.1 dev eth0
192.168.122.0/24 dev eth0  src 192.168.122.2 
/ # ping 192.168.122.1
PING 192.168.122.1 (192.168.122.1): 56 data bytes
64 bytes from 192.168.122.1: seq=0 ttl=64 time=0.985 ms
64 bytes from 192.168.122.1: seq=1 ttl=64 time=0.768 ms
/ # 配置 iptables 的 NAT 规则后，虚拟机可以访问桥接网口以外的网络
/ # ping 10.16.83.1
PING 10.16.83.1 (10.16.83.1): 56 data bytes
64 bytes from 10.16.83.1: seq=0 ttl=254 time=1.561 ms
64 bytes from 10.16.83.1: seq=1 ttl=254 time=1.747 ms
64 bytes from 10.16.83.1: seq=2 ttl=254 time=1.897 ms
64 bytes from 10.16.83.1: seq=3 ttl=254 time=1.559 ms
```

## gdb

按照前面的步骤启动一个 qemu 虚拟机。

在 `$HOME/.gdbinit` 文件中加入下面一行：

```
add-auto-load-safe-path /home/nitrocao/linux-kernel/linux/scripts/gdb/vmlinux-gdb.py
```

具体文件的路径根据自己内核源码路径作相应调整。

打开一个新的终端，用 gdb 加载内核镜像，然后连接到 qemu 启动的 gdb server。我这里在连接到 gdb server 后自动显示的寄存器、汇编代码和栈布局的原因是加载了 gdb 的 peda 插件。没有这个不影响使用。

```shell
$ pwd
/home/nitrocao/linux-kernel
$ gdb ./linux/vmlinux
GNU gdb (GDB) 10.2
Copyright (C) 2021 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-pc-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./linux/vmlinux...
gdb-peda$
gdb-peda$ target remote localhost:1234
Remote debugging using localhost:1234
[----------------------------------registers-----------------------------------]
RAX: 0xffffffff81c5b7b0 --> 0x7e99066666666
RBX: 0x0
RCX: 0x0
RDX: 0x172a
RSI: 0x83
RDI: 0x0
RBP: 0xffffffff82c14940 --> 0x4000 ('')
RSP: 0xffffffff82c03eb8 --> 0xffffffff81c5b982 --> 0x65fbff47f4c8e8fa
RIP: 0xffffffff81c5b7c3 --> 0xccccccccccccccc3
R8 : 0x172a
R9 : 0x3
R10: 0x0
R11: 0x0
R12: 0x0
R13: 0x0
R14: 0x0
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xffffffff81c5b7ba <default_idle+10>:        verw   0x5aa361(%rip)        # 0xffffffff82205b22 <ds.0>
   0xffffffff81c5b7c1 <default_idle+17>:        sti
   0xffffffff81c5b7c2 <default_idle+18>:        hlt
=> 0xffffffff81c5b7c3 <default_idle+19>:        ret
   0xffffffff81c5b7c4:  int3
   0xffffffff81c5b7c5:  int3
   0xffffffff81c5b7c6:  int3
   0xffffffff81c5b7c7:  int3
[------------------------------------stack-------------------------------------]
0000| 0xffffffff82c03eb8 --> 0xffffffff81c5b982 --> 0x65fbff47f4c8e8fa
0008| 0xffffffff82c03ec0 --> 0xffffffff810a2fa6 --> 0x79f0e8ffffff28e9
0016| 0xffffffff82c03ec8 --> 0xffffffff834672e0 --> 0xcccccccccccccccc
0024| 0xffffffff82c03ed0 --> 0x60b0d4164e6a9200
0032| 0xffffffff82c03ed8 --> 0xffff88803ffdf486 --> 0x0
0040| 0xffffffff82c03ee0 --> 0xd9
0048| 0xffffffff82c03ee8 --> 0x24 ('$')
0056| 0xffffffff82c03ef0 --> 0xffffffff834672e0 --> 0xcccccccccccccccc
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGTRAP
0xffffffff81c5b7c3 in default_idle () at arch/x86/kernel/process.c:689
689     }
Warning: Got Ctrl+C / SIGINT!
gdb-peda$
```

`aprops lx`  命令可列出前面加载的脚本中定义的辅助命令和函数：

```shell
gdb-peda$ apropos lx
function lx_clk_core_lookup -- Find struct clk_core by name
function lx_current -- Return current task.
function lx_device_find_by_bus_name -- Find struct device by bus and name (both strings)
function lx_device_find_by_class_name -- Find struct device by class and name (both strings)
function lx_module -- Find module by name and return the module variable.
function lx_per_cpu -- Return per-cpu variable.
function lx_rb_first -- Lookup and return a node from an RBTree
function lx_rb_last -- Lookup and return a node from an RBTree.
function lx_rb_next -- Lookup and return a node from an RBTree.
function lx_rb_prev -- Lookup and return a node from an RBTree.
function lx_task_by_pid -- Find Linux task by PID and return the task_struct variable.
function lx_thread_info -- Calculate Linux thread_info from task variable.
function lx_thread_info_by_pid -- Calculate Linux thread_info from task variable found by pid
lx-clk-summary -- Print clk tree summary
lx-cmdline --  Report the Linux Commandline used in the current kernel.
lx-configdump -- Output kernel config to the filename specified as the command
lx-cpus -- List CPU status arrays
lx-device-list-bus -- Print devices on a bus (or all buses if not specified)
lx-device-list-class -- Print devices in a class (or all classes if not specified)
lx-device-list-tree -- Print a device and its children recursively
lx-dmesg -- Print Linux kernel log buffer.
lx-fdtdump -- Output Flattened Device Tree header and dump FDT blob to the filename
lx-genpd-summary -- Print genpd summary
lx-iomem -- Identify the IO memory resource locations defined by the kernel
lx-ioports -- Identify the IO port resource locations defined by the kernel
lx-list-check -- Verify a list consistency
lx-lsmod -- List currently loaded modules.
lx-mounts -- Report the VFS mounts of the current process namespace.
lx-ps -- Dump Linux tasks.
lx-symbols -- (Re-)load symbols of Linux kernel and currently loaded modules.
lx-timerlist -- Print /proc/timer_list
lx-version --  Report the Linux Version of the current kernel.
gdb-peda$ b __x64_sys_openat  # 给 openat 系统调用下一个断点，然后让虚拟机继续运行。在虚拟机中执行命令 cat /etc/hostname 触发断点
Breakpoint 3 at 0xffffffff8126c570: file fs/open.c, line 1199.
gdb-peda$ c
Continuing.
Breakpoint 3, __x64_sys_openat (regs=0xffffc9000061bf58) at fs/open.c:1199
1199    SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags,
gdb-peda$ lx-ps  # lx-ps 命令列出所有的进程
gdb-peda$ lx-ps
      TASK          PID    COMM
0xffffffff82c14940  0x0  swapper/0
0xffff888003e38000  0x1  init
0xffff888003e38dc0  0x2  kthreadd
0xffff888003e39b80  0x3  rcu_gp
0xffff888003e3a940  0x4  rcu_par_gp
0xffff888003e3b700  0x5  kworker/0:0
0xffff888003e3c4c0  0x6  kworker/0:0H
0xffff888003e3d280  0x7  kworker/u2:0
0xffff888003e3e040  0x8  mm_percpu_wq
0xffff888003e3ee00  0x9  rcu_tasks_rude_
0xffff888003e50000  0xa  rcu_tasks_trace
0xffff888003e50dc0  0xb  ksoftirqd/0
0xffff888003e51b80  0xc  rcu_sched
0xffff888003e52940  0xd  migration/0
0xffff888003e53700  0xe  cpuhp/0
0xffff888003e544c0  0xf  kdevtmpfs
0xffff888003e55280 0x10  netns
0xffff888003e56040 0x11  inet_frag_wq
0xffff888003e56e00 0x12  kauditd
0xffff888003f08000 0x13  oom_reaper
0xffff888003f08dc0 0x14  writeback
0xffff888003f09b80 0x15  kcompactd0
0xffff888003f1b700 0x29  kblockd
0xffff888003f1c4c0 0x2a  blkcg_punt_bio
0xffff888003f1a940 0x2b  ata_sff
0xffff888003f19b80 0x2c  md
0xffff888003f18dc0 0x2d  kworker/0:1
0xffff888003f18000 0x2e  kworker/u2:1
0xffff888003f1d280 0x2f  kworker/0:1H
0xffff888003f1e040 0x30  rpciod
0xffff888003f1ee00 0x31  kworker/u3:0
0xffff888003f16e00 0x32  xprtiod
0xffff888003f16040 0x33  cfg80211
0xffff888003f15280 0x34  kswapd0
0xffff888003f144c0 0x35  nfsiod
0xffff888003f13700 0x37  acpi_thermal_pm
0xffff888003f12940 0x38  kworker/u2:2
0xffff888003f11b80 0x39  scsi_eh_0
0xffff888003f10dc0 0x3a  scsi_tmf_0
0xffff888003f10000 0x3b  scsi_eh_1
0xffff888003f0ee00 0x3c  scsi_tmf_1
0xffff888003f0e040 0x3d  kworker/u2:3
0xffff888003f0d280 0x3e  kworker/0:2
0xffff888003f0c4c0 0x3f  ipv6_addrconf
0xffff888005e70dc0 0x48  sh
0xffff888005e71b80 0x49  init
0xffff888005e72940 0x4a  init
0xffff888005e73700 0x4b  init
0xffff888005e70000 0x51  cat
gdb-peda$ p $lx_current()->tgid    # lx_current() 函数获取当前正在运行进程的 task_struct 结构体指针
$3 = 0x51
```

