# Filesystem



## 目标

在这一部分，我们通过命令行参数指定一个目录作为容器的镜像，并且挂载用户指定的宿主机目录。运行结果：

```shell
➜ sudo ./mydocker --action run --name alpine --image /mnt/alpine --volume /home/nitroc:/home/nitroc:ro -- /bin/sh
l899mrj2f3jfmr97ct9lw9rmuh8l8yhjcwy5t7xz0nkckjpmipe4ovwo3aghyn61
/ # mount
overlay on / type overlay (rw,relatime,lowerdir=/mnt/alpine,upperdir=/mnt/mydocker/containers/l899mrj2f3jfmr97ct9lw9rmuh8l8yhjcwy5t7xz0nkckjpmipe4ovwo3aghyn61/upper/,workdir=/mnt/mydocker/containers/l899mrj2f3jfmr97ct9lw9rmuh8l8yhjcwy5t7xz0nkckjpmipe4ovwo3aghyn61/work/)
/dev/nvme0n1p2 on /home/nitroc type ext4 (ro,relatime)
proc on /proc type proc (rw,relatime)
/ # cat /proc/$$/mountinfo
2366 1958 0:298 / / rw,relatime master:618 - overlay overlay rw,lowerdir=/mnt/alpine,upperdir=/mnt/mydocker/containers/l899mrj2f3jfmr97ct9lw9rmuh8l8yhjcwy5t7xz0nkckjpmipe4ovwo3aghyn61/upper/,workdir=/mnt/mydocker/containers/l899mrj2f3jfmr97ct9lw9rmuh8l8yhjcwy5t7xz0nkckjpmipe4ovwo3aghyn61/work/
2367 2366 259:2 /home/nitroc /home/nitroc ro,relatime - ext4 /dev/nvme0n1p2 rw
1959 2366 0:301 / /proc rw,relatime - proc proc rw
/ #
```



## 实现步骤

首先增加两个命令行选项 `image` 和 `volume`，用于指定镜像的路径和数据目录。  `image` 只是一个字符串，`volume` 是一个类型为 `user_volume_t` 的结构体。`volume` 参数值的解析通过 `parse_volume_options()` 函数实现。通过正则表达式 `^([^:]+):([^:]+)(:rw|:ro)?$`  来处理 `volume` 参数值。  

我们使用 `overlayfs` 联合文件系统配置容器目录。`overlayfs` 需要四个目录，`lowerdir` 目录、`upperdir` 目录、`workdir` 目录以及 `merged` 目录。简言之，将 `lowerdir` 参数指定的目录合并起来，挂载到 `merged` 目录下，对 `merged` 目录的修改会反应到 `upperdir` 目录中，而不会修改底层 `lowerdir` 目录，`workdir` 目录用于文件系统在不同层之间切换时准备相应的文件。

我们的 mydocker 的运行目录为 `/mnt/mydocker`，容器目录为 `/mnt/mydocker/containers`，容器的 `upper` 目录为 `/mnt/mydocker/containers/<id>/upper`，`workdir` 目录为 `/mnt/mydocker/containers/<id>/work`，`merged` 目录为 `/mnt/mydocker/containers/<id>/merged`。

然后 `prepare_dirs()` 函数在父进程中挂载 `overlayfs` 文件系统。

接着在容器进程中将用户指定的宿主机目录挂载到 `merged` 目录中相应的目录下面。然后使用 `MS_SLAVE` 和 `MS_REC` 选项重新挂载容器进程的根目录，使得挂载事件不会传播到其他挂载点。使用绑定挂载以及 `MS_BIND` 和 `MS_REC` 选项挂载 `merged` 目录，这一步的目的是为了满足 `pivot_root(2)` 系统调用的执行条件。将容器进程的工作目录切换到 `merged` 目录。调用 `pivot_root(2)` 系统调用切换容器进程的根挂载点。将容器进程的工作目录切换到新的根目录。取消挂载旧的根挂载点。最后将 `proc` 伪文件系统挂载到新的根目录中。

容器进程终止后取消挂载容器的 `merged` 目录。



## 关键知识

### pivot_root



### overlayfs



### References

* `man 2 mount`
* `man 2 pivot_root`
* https://wiki.archlinux.org/title/Overlay_filesystem
* Mount namepsaces and shared subtrees, https://lwn.net/Articles/689856/
* Mount namespaces, mount propagation, and unbindable mounts, https://lwn.net/Articles/690679/