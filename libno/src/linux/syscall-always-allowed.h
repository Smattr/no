// system calls that we always permit

#ifdef __NR_read
  X(__NR_read)
#endif
#ifdef __NR_write
  X(__NR_write)
#endif
#ifdef __NR_close
  X(__NR_close)
#endif
#ifdef __NR_stat
  X(__NR_stat)
#endif
#ifdef __NR_fstat
  X(__NR_fstat)
#endif
#ifdef __NR_lstat
  X(__NR_lstat)
#endif
#ifdef __NR_poll
  X(__NR_poll)
#endif
#ifdef __NR_lseek
  X(__NR_lseek)
#endif
#ifdef __NR_mmap
  X(__NR_mmap)
#endif
#ifdef __NR_mprotect
  X(__NR_mprotect)
#endif
#ifdef __NR_munmap
  X(__NR_munmap)
#endif
#ifdef __NR_brk
  X(__NR_brk)
#endif
#ifdef __NR_rt_sigaction
  X(__NR_rt_sigaction)
#endif
#ifdef __NR_rt_sigprocmask
  X(__NR_rt_sigprocmask)
#endif
#ifdef __NR_rt_sigreturn
  X(__NR_rt_sigreturn)
#endif
#ifdef __NR_ioctl
  X(__NR_ioctl)
#endif
#ifdef __NR_pread64
  X(__NR_pread64)
#endif
#ifdef __NR_pwrite64
  X(__NR_pwrite64)
#endif
#ifdef __NR_readv
  X(__NR_readv)
#endif
#ifdef __NR_writev
  X(__NR_writev)
#endif
#ifdef __NR_access
  X(__NR_access)
#endif
#ifdef __NR_pipe
  X(__NR_pipe)
#endif
#ifdef __NR_select
  X(__NR_select)
#endif
#ifdef __NR_sched_yield
  X(__NR_sched_yield)
#endif
#ifdef __NR_mremap
  X(__NR_mremap)
#endif
#ifdef __NR_msync
  X(__NR_msync)
#endif
#ifdef __NR_mincore
  X(__NR_mincore)
#endif
#ifdef __NR_madvise
  X(__NR_madvise)
#endif
#ifdef __NR_shmget
  X(__NR_shmget)
#endif
#ifdef __NR_shmat
  X(__NR_shmat)
#endif
#ifdef __NR_shmctl
  X(__NR_shmctl)
#endif
#ifdef __NR_dup
  X(__NR_dup)
#endif
#ifdef __NR_dup2
  X(__NR_dup2)
#endif
#ifdef __NR_pause
  X(__NR_pause)
#endif
#ifdef __NR_nanosleep
  X(__NR_nanosleep)
#endif
#ifdef __NR_getitimer
  X(__NR_getitimer)
#endif
#ifdef __NR_alarm
  X(__NR_alarm)
#endif
#ifdef __NR_setitimer
  X(__NR_setitimer)
#endif
#ifdef __NR_getpid
  X(__NR_getpid)
#endif
#ifdef __NR_sendfile
  X(__NR_sendfile)
#endif
#ifdef __NR_sendto
  X(__NR_sendto)
#endif
#ifdef __NR_recvfrom
  X(__NR_recvfrom)
#endif
#ifdef __NR_sendmsg
  X(__NR_sendmsg)
#endif
#ifdef __NR_recvmsg
  X(__NR_recvmsg)
#endif
#ifdef __NR_shutdown
  X(__NR_shutdown)
#endif
#ifdef __NR_getsockname
  X(__NR_getsockname)
#endif
#ifdef __NR_getpeername
  X(__NR_getpeername)
#endif
#ifdef __NR_setsockopt
  X(__NR_setsockopt)
#endif
#ifdef __NR_getsockopt
  X(__NR_getsockopt)
#endif
#ifdef __NR_clone
  X(__NR_clone)
#endif
#ifdef __NR_fork
  X(__NR_fork)
#endif
#ifdef __NR_vfork
  X(__NR_vfork)
#endif
#ifdef __NR_execve
  X(__NR_execve)
#endif
#ifdef __NR_exit
  X(__NR_exit)
#endif
#ifdef __NR_wait4
  X(__NR_wait4)
#endif
#ifdef __NR_kill
  X(__NR_kill)
#endif
#ifdef __NR_uname
  X(__NR_uname)
#endif
#ifdef __NR_semget
  X(__NR_semget)
#endif
#ifdef __NR_semop
  X(__NR_semop)
#endif
#ifdef __NR_semctl
  X(__NR_semctl)
#endif
#ifdef __NR_shmdt
  X(__NR_shmdt)
#endif
#ifdef __NR_msgget
  X(__NR_msgget)
#endif
#ifdef __NR_msgsnd
  X(__NR_msgsnd)
#endif
#ifdef __NR_msgrcv
  X(__NR_msgrcv)
#endif
#ifdef __NR_msgctl
  X(__NR_msgctl)
#endif
#ifdef __NR_fcntl
  X(__NR_fcntl)
#endif
#ifdef __NR_flock
  X(__NR_flock)
#endif
#ifdef __NR_fsync
  X(__NR_fsync)
#endif
#ifdef __NR_fdatasync
  X(__NR_fdatasync)
#endif
#ifdef __NR_ftruncate
  X(__NR_ftruncate)
#endif
#ifdef __NR_getdents
  X(__NR_getdents)
#endif
#ifdef __NR_getcwd
  X(__NR_getcwd)
#endif
#ifdef __NR_chdir
  X(__NR_chdir)
#endif
#ifdef __NR_fchdir
  X(__NR_fchdir)
#endif
#ifdef __NR_readlink
  X(__NR_readlink)
#endif
#ifdef __NR_chmod
  X(__NR_chmod)
#endif
#ifdef __NR_fchmod
  X(__NR_fchmod)
#endif
#ifdef __NR_fchown
  X(__NR_fchown)
#endif
#ifdef __NR_umask
  X(__NR_umask)
#endif
#ifdef __NR_gettimeofday
  X(__NR_gettimeofday)
#endif
#ifdef __NR_getrlimit
  X(__NR_getrlimit)
#endif
#ifdef __NR_getrusage
  X(__NR_getrusage)
#endif
#ifdef __NR_sysinfo
  X(__NR_sysinfo)
#endif
#ifdef __NR_times
  X(__NR_times)
#endif
#ifdef __NR_ptrace
  X(__NR_ptrace)
#endif
#ifdef __NR_getuid
  X(__NR_getuid)
#endif
#ifdef __NR_syslog
  X(__NR_syslog)
#endif
#ifdef __NR_getgid
  X(__NR_getgid)
#endif
#ifdef __NR_setuid
  X(__NR_setuid)
#endif
#ifdef __NR_setgid
  X(__NR_setgid)
#endif
#ifdef __NR_geteuid
  X(__NR_geteuid)
#endif
#ifdef __NR_getegid
  X(__NR_getegid)
#endif
#ifdef __NR_setpgid
  X(__NR_setpgid)
#endif
#ifdef __NR_getppid
  X(__NR_getppid)
#endif
#ifdef __NR_getpgrp
  X(__NR_getpgrp)
#endif
#ifdef __NR_setsid
  X(__NR_setsid)
#endif
#ifdef __NR_setreuid
  X(__NR_setreuid)
#endif
#ifdef __NR_setregid
  X(__NR_setregid)
#endif
#ifdef __NR_getgroups
  X(__NR_getgroups)
#endif
#ifdef __NR_setgroups
  X(__NR_setgroups)
#endif
#ifdef __NR_setresuid
  X(__NR_setresuid)
#endif
#ifdef __NR_getresuid
  X(__NR_getresuid)
#endif
#ifdef __NR_setresgid
  X(__NR_setresgid)
#endif
#ifdef __NR_getresgid
  X(__NR_getresgid)
#endif
#ifdef __NR_getpgid
  X(__NR_getpgid)
#endif
#ifdef __NR_setfsuid
  X(__NR_setfsuid)
#endif
#ifdef __NR_setfsgid
  X(__NR_setfsgid)
#endif
#ifdef __NR_getsid
  X(__NR_getsid)
#endif
#ifdef __NR_capget
  X(__NR_capget)
#endif
#ifdef __NR_capset
  X(__NR_capset)
#endif
#ifdef __NR_rt_sigpending
  X(__NR_rt_sigpending)
#endif
#ifdef __NR_rt_sigtimedwait
  X(__NR_rt_sigtimedwait)
#endif
#ifdef __NR_rt_sigqueueinfo
  X(__NR_rt_sigqueueinfo)
#endif
#ifdef __NR_rt_sigsuspend
  X(__NR_rt_sigsuspend)
#endif
#ifdef __NR_sigaltstack
  X(__NR_sigaltstack)
#endif
#ifdef __NR_uselib
  X(__NR_uselib)
#endif
#ifdef __NR_personality
  X(__NR_personality)
#endif
#ifdef __NR_ustat
  X(__NR_ustat)
#endif
#ifdef __NR_statfs
  X(__NR_statfs)
#endif
#ifdef __NR_fstatfs
  X(__NR_fstatfs)
#endif
#ifdef __NR_sysfs
  X(__NR_sysfs)
#endif
#ifdef __NR_getpriority
  X(__NR_getpriority)
#endif
#ifdef __NR_setpriority
  X(__NR_setpriority)
#endif
#ifdef __NR_sched_setparam
  X(__NR_sched_setparam)
#endif
#ifdef __NR_sched_getparam
  X(__NR_sched_getparam)
#endif
#ifdef __NR_sched_setscheduler
  X(__NR_sched_setscheduler)
#endif
#ifdef __NR_sched_getscheduler
  X(__NR_sched_getscheduler)
#endif
#ifdef __NR_sched_get_priority_max
  X(__NR_sched_get_priority_max)
#endif
#ifdef __NR_sched_get_priority_min
  X(__NR_sched_get_priority_min)
#endif
#ifdef __NR_sched_rr_get_interval
  X(__NR_sched_rr_get_interval)
#endif
#ifdef __NR_mlock
  X(__NR_mlock)
#endif
#ifdef __NR_munlock
  X(__NR_munlock)
#endif
#ifdef __NR_mlockall
  X(__NR_mlockall)
#endif
#ifdef __NR_munlockall
  X(__NR_munlockall)
#endif
#ifdef __NR_vhangup
  X(__NR_vhangup)
#endif
#ifdef __NR_modify_ldt
  X(__NR_modify_ldt)
#endif
#ifdef __NR__sysctl
  X(__NR__sysctl)
#endif
#ifdef __NR_prctl
  X(__NR_prctl)
#endif
#ifdef __NR_arch_prctl
  X(__NR_arch_prctl)
#endif
#ifdef __NR_adjtimex
  X(__NR_adjtimex)
#endif
#ifdef __NR_setrlimit
  X(__NR_setrlimit)
#endif
#ifdef __NR_chroot
  X(__NR_chroot)
#endif
#ifdef __NR_sync
  X(__NR_sync)
#endif
#ifdef __NR_acct
  X(__NR_acct)
#endif
#ifdef __NR_settimeofday
  X(__NR_settimeofday)
#endif
#ifdef __NR_swapon
  X(__NR_swapon)
#endif
#ifdef __NR_swapoff
  X(__NR_swapoff)
#endif
#ifdef __NR_reboot
  X(__NR_reboot)
#endif
#ifdef __NR_iopl
  X(__NR_iopl)
#endif
#ifdef __NR_ioperm
  X(__NR_ioperm)
#endif
#ifdef __NR_create_module
  X(__NR_create_module)
#endif
#ifdef __NR_init_module
  X(__NR_init_module)
#endif
#ifdef __NR_delete_module
  X(__NR_delete_module)
#endif
#ifdef __NR_get_kernel_syms
  X(__NR_get_kernel_syms)
#endif
#ifdef __NR_query_module
  X(__NR_query_module)
#endif
#ifdef __NR_quotactl
  X(__NR_quotactl)
#endif
#ifdef __NR_nfsservctl
  X(__NR_nfsservctl)
#endif
#ifdef __NR_getpmsg
  X(__NR_getpmsg)
#endif
#ifdef __NR_putpmsg
  X(__NR_putpmsg)
#endif
#ifdef __NR_afs_syscall
  X(__NR_afs_syscall)
#endif
#ifdef __NR_tuxcall
  X(__NR_tuxcall)
#endif
#ifdef __NR_security
  X(__NR_security)
#endif
#ifdef __NR_gettid
  X(__NR_gettid)
#endif
#ifdef __NR_readahead
  X(__NR_readahead)
#endif
#ifdef __NR_fsetxattr
  X(__NR_fsetxattr)
#endif
#ifdef __NR_getxattr
  X(__NR_getxattr)
#endif
#ifdef __NR_lgetxattr
  X(__NR_lgetxattr)
#endif
#ifdef __NR_fgetxattr
  X(__NR_fgetxattr)
#endif
#ifdef __NR_listxattr
  X(__NR_listxattr)
#endif
#ifdef __NR_llistxattr
  X(__NR_llistxattr)
#endif
#ifdef __NR_flistxattr
  X(__NR_flistxattr)
#endif
#ifdef __NR_fremovexattr
  X(__NR_fremovexattr)
#endif
#ifdef __NR_tkill
  X(__NR_tkill)
#endif
#ifdef __NR_time
  X(__NR_time)
#endif
#ifdef __NR_futex
  X(__NR_futex)
#endif
#ifdef __NR_sched_setaffinity
  X(__NR_sched_setaffinity)
#endif
#ifdef __NR_sched_getaffinity
  X(__NR_sched_getaffinity)
#endif
#ifdef __NR_set_thread_area
  X(__NR_set_thread_area)
#endif
#ifdef __NR_io_setup
  X(__NR_io_setup)
#endif
#ifdef __NR_io_destroy
  X(__NR_io_destroy)
#endif
#ifdef __NR_io_getevents
  X(__NR_io_getevents)
#endif
#ifdef __NR_io_submit
  X(__NR_io_submit)
#endif
#ifdef __NR_io_cancel
  X(__NR_io_cancel)
#endif
#ifdef __NR_get_thread_area
  X(__NR_get_thread_area)
#endif
#ifdef __NR_lookup_dcookie
  X(__NR_lookup_dcookie)
#endif
#ifdef __NR_epoll_create
  X(__NR_epoll_create)
#endif
#ifdef __NR_epoll_ctl_old
  X(__NR_epoll_ctl_old)
#endif
#ifdef __NR_epoll_wait_old
  X(__NR_epoll_wait_old)
#endif
#ifdef __NR_remap_file_pages
  X(__NR_remap_file_pages)
#endif
#ifdef __NR_getdents64
  X(__NR_getdents64)
#endif
#ifdef __NR_set_tid_address
  X(__NR_set_tid_address)
#endif
#ifdef __NR_restart_syscall
  X(__NR_restart_syscall)
#endif
#ifdef __NR_semtimedop
  X(__NR_semtimedop)
#endif
#ifdef __NR_fadvise64
  X(__NR_fadvise64)
#endif
#ifdef __NR_timer_create
  X(__NR_timer_create)
#endif
#ifdef __NR_timer_settime
  X(__NR_timer_settime)
#endif
#ifdef __NR_timer_gettime
  X(__NR_timer_gettime)
#endif
#ifdef __NR_timer_getoverrun
  X(__NR_timer_getoverrun)
#endif
#ifdef __NR_timer_delete
  X(__NR_timer_delete)
#endif
#ifdef __NR_clock_settime
  X(__NR_clock_settime)
#endif
#ifdef __NR_clock_gettime
  X(__NR_clock_gettime)
#endif
#ifdef __NR_clock_getres
  X(__NR_clock_getres)
#endif
#ifdef __NR_clock_nanosleep
  X(__NR_clock_nanosleep)
#endif
#ifdef __NR_exit_group
  X(__NR_exit_group)
#endif
#ifdef __NR_epoll_wait
  X(__NR_epoll_wait)
#endif
#ifdef __NR_epoll_ctl
  X(__NR_epoll_ctl)
#endif
#ifdef __NR_tgkill
  X(__NR_tgkill)
#endif
#ifdef __NR_vserver
  X(__NR_vserver)
#endif
#ifdef __NR_mbind
  X(__NR_mbind)
#endif
#ifdef __NR_set_mempolicy
  X(__NR_set_mempolicy)
#endif
#ifdef __NR_get_mempolicy
  X(__NR_get_mempolicy)
#endif
#ifdef __NR_mq_open
  X(__NR_mq_open)
#endif
#ifdef __NR_mq_unlink
  X(__NR_mq_unlink)
#endif
#ifdef __NR_mq_timedsend
  X(__NR_mq_timedsend)
#endif
#ifdef __NR_mq_timedreceive
  X(__NR_mq_timedreceive)
#endif
#ifdef __NR_mq_notify
  X(__NR_mq_notify)
#endif
#ifdef __NR_mq_getsetattr
  X(__NR_mq_getsetattr)
#endif
#ifdef __NR_kexec_load
  X(__NR_kexec_load)
#endif
#ifdef __NR_waitid
  X(__NR_waitid)
#endif
#ifdef __NR_add_key
  X(__NR_add_key)
#endif
#ifdef __NR_request_key
  X(__NR_request_key)
#endif
#ifdef __NR_keyctl
  X(__NR_keyctl)
#endif
#ifdef __NR_ioprio_set
  X(__NR_ioprio_set)
#endif
#ifdef __NR_ioprio_get
  X(__NR_ioprio_get)
#endif
#ifdef __NR_inotify_init
  X(__NR_inotify_init)
#endif
#ifdef __NR_inotify_add_watch
  X(__NR_inotify_add_watch)
#endif
#ifdef __NR_inotify_rm_watch
  X(__NR_inotify_rm_watch)
#endif
#ifdef __NR_migrate_pages
  X(__NR_migrate_pages)
#endif
#ifdef __NR_newfstatat
  X(__NR_newfstatat)
#endif
#ifdef __NR_readlinkat
  X(__NR_readlinkat)
#endif
#ifdef __NR_faccessat
  X(__NR_faccessat)
#endif
#ifdef __NR_pselect6
  X(__NR_pselect6)
#endif
#ifdef __NR_ppoll
  X(__NR_ppoll)
#endif
#ifdef __NR_unshare
  X(__NR_unshare)
#endif
#ifdef __NR_set_robust_list
  X(__NR_set_robust_list)
#endif
#ifdef __NR_get_robust_list
  X(__NR_get_robust_list)
#endif
#ifdef __NR_splice
  X(__NR_splice)
#endif
#ifdef __NR_tee
  X(__NR_tee)
#endif
#ifdef __NR_sync_file_range
  X(__NR_sync_file_range)
#endif
#ifdef __NR_vmsplice
  X(__NR_vmsplice)
#endif
#ifdef __NR_move_pages
  X(__NR_move_pages)
#endif
#ifdef __NR_epoll_pwait
  X(__NR_epoll_pwait)
#endif
#ifdef __NR_signalfd
  X(__NR_signalfd)
#endif
#ifdef __NR_timerfd_create
  X(__NR_timerfd_create)
#endif
#ifdef __NR_eventfd
  X(__NR_eventfd)
#endif
#ifdef __NR_fallocate
  X(__NR_fallocate)
#endif
#ifdef __NR_timerfd_settime
  X(__NR_timerfd_settime)
#endif
#ifdef __NR_timerfd_gettime
  X(__NR_timerfd_gettime)
#endif
#ifdef __NR_signalfd4
  X(__NR_signalfd4)
#endif
#ifdef __NR_eventfd2
  X(__NR_eventfd2)
#endif
#ifdef __NR_epoll_create1
  X(__NR_epoll_create1)
#endif
#ifdef __NR_dup3
  X(__NR_dup3)
#endif
#ifdef __NR_pipe2
  X(__NR_pipe2)
#endif
#ifdef __NR_inotify_init1
  X(__NR_inotify_init1)
#endif
#ifdef __NR_preadv
  X(__NR_preadv)
#endif
#ifdef __NR_pwritev
  X(__NR_pwritev)
#endif
#ifdef __NR_rt_tgsigqueueinfo
  X(__NR_rt_tgsigqueueinfo)
#endif
#ifdef __NR_perf_event_open
  X(__NR_perf_event_open)
#endif
#ifdef __NR_recvmmsg
  X(__NR_recvmmsg)
#endif
#ifdef __NR_fanotify_init
  X(__NR_fanotify_init)
#endif
#ifdef __NR_fanotify_mark
  X(__NR_fanotify_mark)
#endif
#ifdef __NR_prlimit64
  X(__NR_prlimit64)
#endif
#ifdef __NR_name_to_handle_at
  X(__NR_name_to_handle_at)
#endif
#ifdef __NR_clock_adjtime
  X(__NR_clock_adjtime)
#endif
#ifdef __NR_syncfs
  X(__NR_syncfs)
#endif
#ifdef __NR_sendmmsg
  X(__NR_sendmmsg)
#endif
#ifdef __NR_setns
  X(__NR_setns)
#endif
#ifdef __NR_getcpu
  X(__NR_getcpu)
#endif
#ifdef __NR_process_vm_readv
  X(__NR_process_vm_readv)
#endif
#ifdef __NR_process_vm_writev
  X(__NR_process_vm_writev)
#endif
#ifdef __NR_kcmp
  X(__NR_kcmp)
#endif
#ifdef __NR_finit_module
  X(__NR_finit_module)
#endif
#ifdef __NR_sched_setattr
  X(__NR_sched_setattr)
#endif
#ifdef __NR_sched_getattr
  X(__NR_sched_getattr)
#endif
#ifdef __NR_seccomp
  X(__NR_seccomp)
#endif
#ifdef __NR_getrandom
  X(__NR_getrandom)
#endif
#ifdef __NR_memfd_create
  X(__NR_memfd_create)
#endif
#ifdef __NR_kexec_file_load
  X(__NR_kexec_file_load)
#endif
#ifdef __NR_bpf
  X(__NR_bpf)
#endif
#ifdef __NR_execveat
  X(__NR_execveat)
#endif
#ifdef __NR_userfaultfd
  X(__NR_userfaultfd)
#endif
#ifdef __NR_membarrier
  X(__NR_membarrier)
#endif
#ifdef __NR_mlock2
  X(__NR_mlock2)
#endif
#ifdef __NR_copy_file_range
  X(__NR_copy_file_range)
#endif
#ifdef __NR_preadv2
  X(__NR_preadv2)
#endif
#ifdef __NR_pwritev2
  X(__NR_pwritev2)
#endif
#ifdef __NR_pkey_mprotect
  X(__NR_pkey_mprotect)
#endif
#ifdef __NR_pkey_alloc
  X(__NR_pkey_alloc)
#endif
#ifdef __NR_pkey_free
  X(__NR_pkey_free)
#endif
#ifdef __NR_statx
  X(__NR_statx)
#endif
