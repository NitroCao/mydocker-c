# mydocker-c

此项目旨在通过用 C 语言实现一个简单的 Docker，了解 Docker 的运行原理，包括但不限于阅读分析相关的 Linux 内核源码。

## 预备知识

* C 语言基础。本文不会介绍基础的 C 语言语法。
* Linux 系统编程基础。本文不会介绍基础的 Linux 系统编程内容，如 open、read、write、mmap、stat 等，而是着重于跟 Docker 实现相关的内容。

* Docker 基础。本文不会详细介绍 Docker 的基础操作，而是着重于基础操作背后的实现原理。

## 学习建议

强烈建议阅读本文之前先学习《自己动手写 Docker》，先使用 Go 语言实现一个简单的 Docker。之后再学习本文。或者边用 Go 写，边用 C 写。

## 目录

* 构造一个基本的容器（[basic](docs/READMD.md)）

