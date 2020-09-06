// syscalls that can be used to cause modifications to the file system

#ifdef __NR_open
  X(__NR_open)
#endif
#ifdef __NR_truncate
  X(__NR_truncate)
#endif
#ifdef __NR_rename
  X(__NR_rename)
#endif
#ifdef __NR_mkdir
  X(__NR_mkdir)
#endif
#ifdef __NR_rmdir
  X(__NR_rmdir)
#endif
#ifdef __NR_creat
  X(__NR_creat)
#endif
#ifdef __NR_link
  X(__NR_link)
#endif
#ifdef __NR_unlink
  X(__NR_unlink)
#endif
#ifdef __NR_symlink
  X(__NR_symlink)
#endif
#ifdef __NR_chown
  X(__NR_chown)
#endif
#ifdef __NR_lchown
  X(__NR_lchown)
#endif
#ifdef __NR_utime
  X(__NR_utime)
#endif
#ifdef __NR_mknod
  X(__NR_mknod)
#endif
#ifdef __NR_pivot_root
  X(__NR_pivot_root)
#endif
#ifdef __NR_mount
  X(__NR_mount)
#endif
#ifdef __NR_umount2
  X(__NR_umount2)
#endif
#ifdef __NR_setxattr
  X(__NR_setxattr)
#endif
#ifdef __NR_lsetxattr
  X(__NR_lsetxattr)
#endif
#ifdef __NR_removexattr
  X(__NR_removexattr)
#endif
#ifdef __NR_lremovexattr
  X(__NR_lremovexattr)
#endif
#ifdef __NR_utimes
  X(__NR_utimes)
#endif
#ifdef __NR_openat
  X(__NR_openat)
#endif
#ifdef __NR_mkdirat
  X(__NR_mkdirat)
#endif
#ifdef __NR_mknodat
  X(__NR_mknodat)
#endif
#ifdef __NR_fchownat
  X(__NR_fchownat)
#endif
#ifdef __NR_futimesat
  X(__NR_futimesat)
#endif
#ifdef __NR_unlinkat
  X(__NR_unlinkat)
#endif
#ifdef __NR_renameat
  X(__NR_renameat)
#endif
#ifdef __NR_linkat
  X(__NR_linkat)
#endif
#ifdef __NR_symlinkat
  X(__NR_symlinkat)
#endif
#ifdef __NR_fchmodat
  X(__NR_fchmodat)
#endif
#ifdef __NR_utimensat
  X(__NR_utimensat)
#endif
#ifdef __NR_open_by_handle_at
  X(__NR_open_by_handle_at)
#endif
#ifdef __NR_renameat2
  X(__NR_renameat2)
#endif
