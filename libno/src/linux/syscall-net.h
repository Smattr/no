// system calls related to networking setup

#ifdef __NR_socket
  X(__NR_socket)
#endif
#ifdef __NR_connect
  X(__NR_connect)
#endif
#ifdef __NR_accept
  X(__NR_accept)
#endif
#ifdef __NR_bind
  X(__NR_bind)
#endif
#ifdef __NR_listen
  X(__NR_listen)
#endif
#ifdef __NR_socketpair
  X(__NR_socketpair)
#endif
#ifdef __NR_sethostname
  X(__NR_sethostname)
#endif
#ifdef __NR_setdomainname
  X(__NR_setdomainname)
#endif
#ifdef __NR_accept4
  X(__NR_accept4)
#endif
#ifdef __NR_socketcall
  X(__NR_socketcall)
#endif
