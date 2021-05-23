## List of capabilities

* CAP_AUDIT_CONTROL*  (since Linux 2.6.11)
Enable and disable kernel auditing; change auditing filter
rules; retrieve auditing status and filtering rules.
* CAP_AUDIT_READ*  (since Linux 3.16)
              Allow reading the audit log via a multicast netlink
              socket.

* CAP_AUDIT_WRITE*  (since Linux 2.6.11)
              Write records to kernel auditing log.

* CAP_BLOCK_SUSPEND*  (since Linux 3.5)
              Employ features that can block system suspend ([epoll(7)](https://man7.org/linux/man-pages/man7/epoll.7.html)
              * EPOLLWAKEUP* , _/proc/sys/wake_lock_).

* CAP_BPF*  (since Linux 5.8)
              - Employ privileged BPF operations; see [bpf(2)](https://man7.org/linux/man-pages/man2/bpf.2.html) and
              [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).
			  - This capability was added in Linux 5.8 to separate out BPF
              functionality from the overloaded * CAP_SYS_ADMIN* 
              capability.

* CAP_CHECKPOINT_RESTORE*  (since Linux 5.9)
              * Update _/proc/sys/kernel/ns_last_pid_ (see
                [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html));
              - employ the _set_tid_ feature of [clone3(2)](https://man7.org/linux/man-pages/man2/clone3.2.html);
              - read the contents of the symbolic links in
                _/proc/[pid]/map_files_ for other processes.
              - This capability was added in Linux 5.9 to separate out
              checkpoint/restore functionality from the overloaded
              * CAP_SYS_ADMIN*  capability.

* CAP_CHOWN
              Make arbitrary changes to file UIDs and GIDs (see
              [chown(2)](https://man7.org/linux/man-pages/man2/chown.2.html)).

* CAP_DAC_OVERRIDE
              Bypass file read, write, and execute permission checks.
              (DAC is an abbreviation of "discretionary access
              control".)

* CAP_DAC_READ_SEARCH
              - Bypass file read permission checks and directory read
                and execute permission checks;
              - invoke [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html);
              - use the [linkat(2)](https://man7.org/linux/man-pages/man2/linkat.2.html) * AT_EMPTY_PATH*  flag to create a link to
                a file referred to by a file descriptor.

* CAP_FOWNER
              - Bypass permission checks on operations that normally
                require the filesystem UID of the process to match the
                UID of the file (e.g., [chmod(2)](https://man7.org/linux/man-pages/man2/chmod.2.html), [utime(2)](https://man7.org/linux/man-pages/man2/utime.2.html)), excluding
                those operations covered by * CAP_DAC_OVERRIDE*  and
                * CAP_DAC_READ_SEARCH* ;
              - set inode flags (see [ioctl_iflags(2)](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)) on arbitrary
                files;
              - set Access Control Lists (ACLs) on arbitrary files;
              - ignore directory sticky bit on file deletion;
              - modify _user_ extended attributes on sticky directory
                owned by any user;
              - specify * O_NOATIME*  for arbitrary files in [open(2)](https://man7.org/linux/man-pages/man2/open.2.html) and
                [fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html).

* CAP_FSETID
              - Don't clear set-user-ID and set-group-ID mode bits when
                a file is modified;
              - set the set-group-ID bit for a file whose GID does not
                match the filesystem or any of the supplementary GIDs of
                the calling process.

* CAP_IPC_LOCK
              Lock memory ([mlock(2)](https://man7.org/linux/man-pages/man2/mlock.2.html), [mlockall(2)](https://man7.org/linux/man-pages/man2/mlockall.2.html), [mmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html), [shmctl(2)](https://man7.org/linux/man-pages/man2/shmctl.2.html)).

* CAP_IPC_OWNER
              Bypass permission checks for operations on System V IPC
              objects.

* CAP_KILL
              Bypass permission checks for sending signals (see
              [kill(2)](https://man7.org/linux/man-pages/man2/kill.2.html)).  This includes use of the [ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html) * KDSIGACCEPT* 
              operation.

* CAP_LEASE  (since Linux 2.4)
              Establish leases on arbitrary files (see [fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html)).

* CAP_LINUX_IMMUTABLE
              Set the * FS_APPEND_FL*  and * FS_IMMUTABLE_FL*  inode flags (see
              [ioctl_iflags(2)](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)).

* CAP_MAC_ADMIN  (since Linux 2.6.25)
              Allow MAC configuration or state changes.  Implemented for
              the Smack Linux Security Module (LSM).

* CAP_MAC_OVERRIDE  (since Linux 2.6.25)
              Override Mandatory Access Control (MAC).  Implemented for
              the Smack LSM.

* CAP_MKNOD  (since Linux 2.4)
              Create special files using [mknod(2)](https://man7.org/linux/man-pages/man2/mknod.2.html).

* CAP_NET_ADMIN
              Perform various network-related operations:
              - interface configuration;
              - administration of IP firewall, masquerading, and
                accounting;
              - modify routing tables;
              - bind to any address for transparent proxying;
              - set type-of-service (TOS);
              - clear driver statistics;
              - set promiscuous mode;
              - enabling multicasting;
              - use [setsockopt(2)](https://man7.org/linux/man-pages/man2/setsockopt.2.html) to set the following socket options:
                * SO_DEBUG* , * SO_MARK* , * SO_PRIORITY*  (for a priority outside
                the range 0 to 6), * SO_RCVBUFFORCE* , and * SO_SNDBUFFORCE* .

* CAP_NET_BIND_SERVICE
              Bind a socket to Internet domain privileged ports (port
              numbers less than 1024).

* CAP_NET_BROADCAST
              (Unused)  Make socket broadcasts, and listen to
              multicasts.

* CAP_NET_RAW 
              * Use RAW and PACKET sockets;
              * bind to any address for transparent proxying.

* CAP_PERFMON  (since Linux 5.8)
              Employ various performance-monitoring mechanisms,
              including:
              - call [perf_event_open(2)](https://man7.org/linux/man-pages/man2/perf_event_open.2.html);
              - employ various BPF operations that have performance
                implications.
              This capability was added in Linux 5.8 to separate out
              performance monitoring functionality from the overloaded
              * CAP_SYS_ADMIN*  capability.  See also the kernel source file
              _Documentation/admin-guide/perf-security.rst_.

* CAP_SETGID
              - Make arbitrary manipulations of process GIDs and
                supplementary GID list;
              - forge GID when passing socket credentials via UNIX
                domain sockets;
              - write a group ID mapping in a user namespace (see
                [user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)).

* CAP_SETFCAP  (since Linux 2.6.24)
              Set arbitrary capabilities on a file.

* CAP_SETPCAP 
              If file capabilities are supported (i.e., since Linux
              2.6.24): add any capability from the calling thread's
              bounding set to its inheritable set; drop capabilities
              from the bounding set (via [prctl(2)](https://man7.org/linux/man-pages/man2/prctl.2.html) * PR_CAPBSET_DROP* ); make
              changes to the _securebits_ flags.
              If file capabilities are not supported (i.e., kernels
              before Linux 2.6.24): grant or remove any capability in
              the caller's permitted capability set to or from any other
              process.  (This property of * CAP_SETPCAP*  is not available
              when the kernel is configured to support file
              capabilities, since * CAP_SETPCAP*  has entirely different
              semantics for such kernels.)

* CAP_SETUID
              - Make arbitrary manipulations of process UIDs ([setuid(2)](https://man7.org/linux/man-pages/man2/setuid.2.html),
                [setreuid(2)](https://man7.org/linux/man-pages/man2/setreuid.2.html), [setresuid(2)](https://man7.org/linux/man-pages/man2/setresuid.2.html), [setfsuid(2)](https://man7.org/linux/man-pages/man2/setfsuid.2.html));
              - forge UID when passing socket credentials via UNIX
                domain sockets;
              - write a user ID mapping in a user namespace (see
                [user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)).

* CAP_SYS_ADMIN 
              _Note_: this capability is overloaded; see _Notes to kernel_
              _developers_, below.
              - Perform a range of system administration operations
                including: [quotactl(2)](https://man7.org/linux/man-pages/man2/quotactl.2.html), [mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html), [umount(2)](https://man7.org/linux/man-pages/man2/umount.2.html),
                [pivot_root(2)](https://man7.org/linux/man-pages/man2/pivot_root.2.html), [swapon(2)](https://man7.org/linux/man-pages/man2/swapon.2.html), [swapoff(2)](https://man7.org/linux/man-pages/man2/swapoff.2.html), [sethostname(2)](https://man7.org/linux/man-pages/man2/sethostname.2.html),
                and [setdomainname(2)](https://man7.org/linux/man-pages/man2/setdomainname.2.html);
              - perform privileged [syslog(2)](https://man7.org/linux/man-pages/man2/syslog.2.html) operations (since Linux
                2.6.37, * CAP_SYSLOG*  should be used to permit such
                operations);
              - perform * VM86_REQUEST_IRQ vm86* (2) command;
              - access the same checkpoint/restore functionality that is
                governed by * CAP_CHECKPOINT_RESTORE*  (but the latter,
                weaker capability is preferred for accessing that
                functionality).
              - perform the same BPF operations as are governed by
                * CAP_BPF*  (but the latter, weaker capability is preferred
                for accessing that functionality).
              - employ the same performance monitoring mechanisms as are
                governed by * CAP_PERFMON*  (but the latter, weaker
                capability is preferred for accessing that
                functionality).
              - perform * IPC_SET*  and * IPC_RMID*  operations on arbitrary
                System V IPC objects;
              - override * RLIMIT_NPROC*  resource limit;
              - perform operations on _trusted_ and _security_ extended
                attributes (see [xattr(7)](https://man7.org/linux/man-pages/man7/xattr.7.html));
              - use [lookup_dcookie(2)](https://man7.org/linux/man-pages/man2/lookup_dcookie.2.html);
              - use [ioprio_set(2)](https://man7.org/linux/man-pages/man2/ioprio_set.2.html) to assign * IOPRIO_CLASS_RT*  and (before
                Linux 2.6.25) * IOPRIO_CLASS_IDLE*  I/O scheduling classes;
              - forge PID when passing socket credentials via UNIX
                domain sockets;
              - exceed _/proc/sys/fs/file-max_, the system-wide limit on
                the number of open files, in system calls that open
                files (e.g., [accept(2)](https://man7.org/linux/man-pages/man2/accept.2.html), [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html), [open(2)](https://man7.org/linux/man-pages/man2/open.2.html), [pipe(2)](https://man7.org/linux/man-pages/man2/pipe.2.html));
              - employ * CLONE_* * flags that create new namespaces with
                [clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html) and [unshare(2)](https://man7.org/linux/man-pages/man2/unshare.2.html) (but, since Linux 3.8, creating
                user namespaces does not require any capability);
              - access privileged _perf_ event information;
              - call [setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html)(requires * CAP_SYS_ADMIN*  in the _target_
                namespace);
              - call [fanotify_init(2)](https://man7.org/linux/man-pages/man2/fanotify_init.2.html);
              - perform privileged * KEYCTL_CHOWN*  and * KEYCTL_SETPERM* 
                [keyctl(2)](https://man7.org/linux/man-pages/man2/keyctl.2.html) operations;
              - perform [madvise(2)](https://man7.org/linux/man-pages/man2/madvise.2.html) * MADV_HWPOISON*  operation;
              - employ the * TIOCSTI ioctl* (2) to insert characters into
                the input queue of a terminal other than the caller's
                controlling terminal;
              - employ the obsolete [nfsservctl(2)](https://man7.org/linux/man-pages/man2/nfsservctl.2.html) system call;
              - employ the obsolete [bdflush(2)](https://man7.org/linux/man-pages/man2/bdflush.2.html) system call;
              - perform various privileged block-device [ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html)
                operations;
              - perform various privileged filesystem [ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html)
                operations;
              - perform privileged [ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html) operations on the
                _/dev/random_ device (see [random(4)](https://man7.org/linux/man-pages/man4/random.4.html));
              - install a [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html) filter without first having to set
                the _no_new_privs_ thread attribute;
              - modify allow/deny rules for device control groups;
              - employ the [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) * PTRACE_SECCOMP_GET_FILTER*  operation
                to dump tracee's seccomp filters;
              - employ the [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) * PTRACE_SETOPTIONS*  operation to
                suspend the tracee's seccomp protections (i.e., the
                * PTRACE_O_SUSPEND_SECCOMP*  flag);
              - perform administrative operations on many device
                drivers;
              - modify autogroup nice values by writing to
                _/proc/[pid]/autogroup_ (see [sched(7)](https://man7.org/linux/man-pages/man7/sched.7.html)).

* CAP_SYS_BOOT
              Use [reboot(2)](https://man7.org/linux/man-pages/man2/reboot.2.html) and [kexec_load(2)](https://man7.org/linux/man-pages/man2/kexec_load.2.html).

* CAP_SYS_CHROOT
              - Use [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html);
              - change mount namespaces using [setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html).

* CAP_SYS_MODULE
              - Load and unload kernel modules (see [init_module(2)](https://man7.org/linux/man-pages/man2/init_module.2.html) and
                [delete_module(2)](https://man7.org/linux/man-pages/man2/delete_module.2.html));
              - in kernels before 2.6.25: drop capabilities from the
                system-wide capability bounding set.

* CAP_SYS_NICE
              - Lower the process nice value ([nice(2)](https://man7.org/linux/man-pages/man2/nice.2.html), [setpriority(2)](https://man7.org/linux/man-pages/man2/setpriority.2.html))
                and change the nice value for arbitrary processes;
              - set real-time scheduling policies for calling process,
                and set scheduling policies and priorities for arbitrary
                processes ([sched_setscheduler(2)](https://man7.org/linux/man-pages/man2/sched_setscheduler.2.html), [sched_setparam(2)](https://man7.org/linux/man-pages/man2/sched_setparam.2.html),
                [sched_setattr(2)](https://man7.org/linux/man-pages/man2/sched_setattr.2.html));
              - set CPU affinity for arbitrary processes
                ([sched_setaffinity(2)](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html));
              - set I/O scheduling class and priority for arbitrary
                processes ([ioprio_set(2)](https://man7.org/linux/man-pages/man2/ioprio_set.2.html));
              - apply [migrate_pages(2)](https://man7.org/linux/man-pages/man2/migrate_pages.2.html) to arbitrary processes and allow
                processes to be migrated to arbitrary nodes;
              - apply [move_pages(2)](https://man7.org/linux/man-pages/man2/move_pages.2.html) to arbitrary processes;
              - use the * MPOL_MF_MOVE_ALL*  flag with [mbind(2)](https://man7.org/linux/man-pages/man2/mbind.2.html) and
                [move_pages(2)](https://man7.org/linux/man-pages/man2/move_pages.2.html).

* CAP_SYS_PACCT
              Use [acct(2)](https://man7.org/linux/man-pages/man2/acct.2.html).

* CAP_SYS_PTRACE
              - Trace arbitrary processes using [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html);
              - apply [get_robust_list(2)](https://man7.org/linux/man-pages/man2/get_robust_list.2.html) to arbitrary processes;
              - transfer data to or from the memory of arbitrary
                processes using [process_vm_readv(2)](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html) and
                [process_vm_writev(2)](https://man7.org/linux/man-pages/man2/process_vm_writev.2.html);
              - inspect processes using [kcmp(2)](https://man7.org/linux/man-pages/man2/kcmp.2.html).

* CAP_SYS_RAWIO
              - Perform I/O port operations ([iopl(2)](https://man7.org/linux/man-pages/man2/iopl.2.html) and [ioperm(2)](https://man7.org/linux/man-pages/man2/ioperm.2.html));
              - access _/proc/kcore_;
              - employ the * FIBMAP ioctl* (2) operation;
              - open devices for accessing x86 model-specific registers
                (MSRs, see [msr(4)](https://man7.org/linux/man-pages/man4/msr.4.html));
              - update _/proc/sys/vm/mmap_min_addr_;
              - create memory mappings at addresses below the value
                specified by _/proc/sys/vm/mmap_min_addr_;
              - map files in _/proc/bus/pci_;
              - open _/dev/mem_ and _/dev/kmem_;
              - perform various SCSI device commands;
              - perform certain operations on [hpsa(4)](https://man7.org/linux/man-pages/man4/hpsa.4.html) and [cciss(4)](https://man7.org/linux/man-pages/man4/cciss.4.html)
                devices;
              - perform a range of device-specific operations on other
                devices.

* CAP_SYS_RESOURCE 
              - Use reserved space on ext2 filesystems;
              - make [ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html) calls controlling ext3 journaling;
              - override disk quota limits;
              - increase resource limits (see [setrlimit(2)](https://man7.org/linux/man-pages/man2/setrlimit.2.html));
              - override * RLIMIT_NPROC*  resource limit;
              - override maximum number of consoles on console
                allocation;
              - override maximum number of keymaps;
              - allow more than 64hz interrupts from the real-time
                clock;
              - raise _msg_qbytes_ limit for a System V message queue
                above the limit in _/proc/sys/kernel/msgmnb_ (see [msgop(2)](https://man7.org/linux/man-pages/man2/msgop.2.html)
                and [msgctl(2)](https://man7.org/linux/man-pages/man2/msgctl.2.html));
              - allow the * RLIMIT_NOFILE*  resource limit on the number of
                "in-flight" file descriptors to be bypassed when passing
                file descriptors to another process via a UNIX domain
                socket (see [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html));
              - override the _/proc/sys/fs/pipe-size-max_ limit when
                setting the capacity of a pipe using the * F_SETPIPE_SZ* 
                [fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html) command;
              - use * F_SETPIPE_SZ*  to increase the capacity of a pipe
                above the limit specified by _/proc/sys/fs/pipe-max-size_;
              - override _/proc/sys/fs/mqueue/queues_max,_
                _/proc/sys/fs/mqueue/msg_max,_ and
                _/proc/sys/fs/mqueue/msgsize_max_ limits when creating
                POSIX message queues (see [mq_overview(7)](https://man7.org/linux/man-pages/man7/mq_overview.7.html));
              - employ the [prctl(2)](https://man7.org/linux/man-pages/man2/prctl.2.html) * PR_SET_MM*  operation;
              - set _/proc/[pid]/oom_score_adj_ to a value lower than the
                value last set by a process with * CAP_SYS_RESOURCE* .

* CAP_SYS_TIME 
              Set system clock ([settimeofday(2)](https://man7.org/linux/man-pages/man2/settimeofday.2.html), [stime(2)](https://man7.org/linux/man-pages/man2/stime.2.html), [adjtimex(2)](https://man7.org/linux/man-pages/man2/adjtimex.2.html));
              set real-time (hardware) clock.

* CAP_SYS_TTY_CONFIG
              Use [vhangup(2)](https://man7.org/linux/man-pages/man2/vhangup.2.html); employ various privileged [ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html)
              operations on virtual terminals.

* CAP_SYSLOG  (since Linux 2.6.37)
              - Perform privileged [syslog(2)](https://man7.org/linux/man-pages/man2/syslog.2.html) operations.  See [syslog(2)](https://man7.org/linux/man-pages/man2/syslog.2.html)
                for information on which operations require privilege.
              - View kernel addresses exposed via _/proc_ and other
                interfaces when _/proc/sys/kernel/kptr_restrict_ has the
                value 1.  (See the discussion of the _kptr_restrict_ in
                [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).)

* CAP_WAKE_ALARM  (since Linux 3.0)
              Trigger something that will wake up the system (set
              * CLOCK_REALTIME_ALARM*  and * CLOCK_BOOTTIME_ALARM*  timers).


## Check capabilities sets

```bash
cat /proc/$pid/task/$thread_n°/status

# Effective : Verified for each privileged action
# Permitted : capabilities that can be enabled in effective or in inheritable set
# inheritable : passed during program load as permitted set
# ambient : preserved during program load to pass capabilities (EUID != 0)
# bounding : limiting superset

```

[Transform cap code to human sense](https://github.com/jhunt/caps)

## Process creation and transformation

* System call fork()
		-	Create new process as clone of existing process
		-	Capability sets copied
* System call execve()
		-	Load new code and data from program file
		-	When process ' EUID is 0 or program file is setuid root
					All permitted and effective capabilities enabled
					
* Specify capabilities in services
		-	In the \[service\] tab add the field:
			 			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; * *AmbientCapabilities=CAPS_HERE*
						&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; * *CapabilityBoundingSet=CAPS_HERE*
		- Even if no users was specify and so the root user is passed by default,
bounding capabilities will restrict the program to them

## Capabilities in docker

* No nice capabilities set to docker by default
* You can use following commands to manage capabilities in docker args:
```bash
docker run --cap-add list image cmd  	# not for normal user
		   --cap-drop list
           --user name|uid		# no capabilties
```

## Runing executable file

* You can modify capabilities of program files
		- Using inheritable set we can reduce new permitted set of thread after execve()
		- Using permitted set we can extend new permitted set of thread after execve()
* We can change and show capabilities on executable file as follow
```bash
getcap /bin/FILE
setcap CAPNAME=pe /bin/FILE # 'p' refer to permitted set & 'e' to effective bit
```

[Nice presentation to base this cheatsheet](https://www.youtube.com/watch?v=WYC6DHzWzFQ)

[Little bit of hacks](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities)