## Mane pages

-   See [Guide: 10.3.3. Manual Pages for Services](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Fixing_Problems.html#sect-Security-Enhanced_Linux-Fixing_Problems-Manual_Pages_for_Services)

## Enable or disable SELinux

-   See `man semanage-permissive` and [⁠Guide: 10.3.4. Permissive Domains](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Fixing_Problems.html#sect-Security-Enhanced_Linux-Fixing_Problems-Permissive_Domains)
-   See [Guide: 1.4. SELinux States and Modes](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Introduction-SELinux_Modes.html)

```bash
# For the whole system
setenforce 0 # Disable
setenforce 1 # Enable

# Disable only for specific domains
semanage permissive --add logrotate_t
semanage permissive -a httpd_t

# Enable only for specific domains

semanage permissive --del logrotate_t
semanage permissive -d httpd_t

# Disable all permissive domains
semodule -d permissivedomains

#Enable back any previously-set permissive domains
semodule -e permissivedomains
```

## Checking enforcing/permissive/disabled status

```bash
sestatus   # Show current & config-file status
getenforce   # Show current status
grep ^SELINUX= /etc/selinux/config   # Show config-file (permanent) status
grep -e enforcing= -e selinux= /etc/default/grub /etc/grub2.cfg   # Check for kernel args
```

## Check permissive domains
```bash
semodule -l | grep permissive
```

## File labels

Every file gets a label. Policy determines what a process domain can do to files of each label.

-   See `man semanage-fcontext` and [Guide: ⁠10.2.1. Labeling Problems](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Top_Three_Causes_of_Problems.html#sect-Security-Enhanced_Linux-Top_Three_Causes_of_Problems-Labeling_Problems)
        
```bash
# Set a file type on a directory
semanage fcontext --add samba_share_t "/path/to/dir(/.*)?" && restorecon -RF /path/to/dir
semanage fcontext -a httpd_sys_content_t "/path(/.*)?" && restorecon -RF /path
    
# Create an alternate location (equivalency rule) based on an existing directory (which is useful because it recursively includes rules)

semanage fcontext -a -e /var/www /web && restorecon -RF /web
semanage fcontext -a -e /home /our/home && restorecon -RF /our/home
    
# Check what a particular \[source\] process domain can do to a particular \[target\] file type
    
sesearch -CA -s httpd_t -t var_log_t
```

## Network port labels
-   See `man semanage-port` and [Guide: 10.2.2. How are Confined Services Running?](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Top_Three_Causes_of_Problems.html#sect-Security-Enhanced_Linux-Top_Three_Causes_of_Problems-How_are_Confined_Services_Running)

```bash
# Check for port labels by domains/services
semanage port -l | grep http   # Look for http-labeled ports
semanage port -l | grep ssh   # Look for ssh-labeled ports
semanage port -l | grep 3333   # Look for a specific port
man httpd_selinux
man sshd_selinux
sesearch -CA -s httpd_t -c tcp_socket -p name_bind   # Look for tcp port types that a particular domain is allowed to bind to

#Permanently set labels on specific network ports
semanage port -a -t http_port_t -p tcp 3333   # Permanently add a label to a specific port
semanage port -a -t ssh_port_t -p tcp 2222
```

## Boolean on/off switches

-   See `man semanage-boolean` and [Guide: 10.2.2. How are Confined Services Running?](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Top_Three_Causes_of_Problems.html#sect-Security-Enhanced_Linux-Top_Three_Causes_of_Problems-How_are_Confined_Services_Running)

```bash
# Check booleans for domains
semanage boolean -l | grep httpd
man httpd_selinux

# Set booleans
setsebool httpd_can_sendmail on   # Immediate & temporary
setsebool -P httpd_use_nfs on   # Permanent & takes a minute to rebuild policy
setsebool -P httpd_builtin_scripting=off httpd_tmp_exec=1   # "on" and "1", "off" and "0" all work; equals sign optional unless trying to do multiple booleans at once
```

## Inspect audit "access vector cache" records

-   See `man ausearch` and `man aureport` and [Guide: 10.3.5. Searching For and Viewing Denials](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Fixing_Problems.html#sect-Security-Enhanced_Linux-Fixing_Problems-Searching_For_and_Viewing_Denials) and [Guide: 10.3.6. Raw Audit Messages](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Fixing_Problems.html#sect-Security-Enhanced_Linux-Fixing_Problems-Raw_Audit_Messages)

```bash
#Get an overview
aureport -a   # Get a report of all AVC denial events
aureport -i -a | awk 'NR==4 || NR>5' | column -t   # Interpret syscall numbers to names; show in columnized list

#Go deeper
ausearch -i -m avc   # Show all from standard audit.log files
ausearch -i -m avc -ts recent   # Show last 10 minutes
ausearch -i -m avc -ts today -c httpd   # Show particular command since midnight
ausearch -i -m avc -ts 16:05 -su httpd_t   # Show particular source (subject) SELinux context since 16:05 PM
```

## Confining users

-   See `man semanage-login` and `man semanage-user` and [Guide: ⁠3.3. Confined and Unconfined Users](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Targeted_Policy-Confined_and_Unconfined_Users.html) and [Guide: 6. Confining Users](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/chap-Security-Enhanced_Linux-Confining_Users.html)

```bash
Create user mapped to guest_u
useradd -Z guest_u newuserbob #guest_u represent the no internet, no sudo su, no blablabla 

#Disallow everything from /tmp or $HOME
~]# setsebool -P guest_exec_content=off xguest_exec_content=off
~]# semanage boolean -l | grep exec_content
auditadm_exec_content          (on   ,   on)  Allow auditadm to exec content
guest_exec_content             (off  ,  off)  Allow guest to exec content
dbadm_exec_content             (on   ,   on)  Allow dbadm to exec content
xguest_exec_content            (off  ,  off)  Allow xguest to exec content
secadm_exec_content            (on   ,   on)  Allow secadm to exec content
logadm_exec_content            (on   ,   on)  Allow logadm to exec content
user_exec_content              (on   ,   on)  Allow user to exec content
staff_exec_content             (on   ,   on)  Allow staff to exec content
sysadm_exec_content            (on   ,   on)  Allow sysadm to exec content

#Confine existing user, map it to user_u (no sudo or other setuid apps)
semanage login -a -s user_u existinguseralice
```

## Fix SELinux denials by allowing requested access

-   See `man audit2allow` and [Guide: 10.3.8. Allowing Access: audit2allow](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/SELinux_Users_and_Administrators_Guide/sect-Security-Enhanced_Linux-Troubleshooting-Fixing_Problems.html#sect-Security-Enhanced_Linux-Fixing_Problems-Allowing_Access_audit2allow)

```bash
ausearch -i -m avc | grep xxxx | audit2allow
```




[[SystemD Services]]

## Exemple

simpleserver.te
```bash
policy_module(simpleserver, 1.0.0)

require {
        type bin_t;
        type node_t;
        type pegasus_http_port_t;
        type httpd_sys_content_t;
};

########################################
#
# Declarations
#

type simpleserver_t;
type simpleserver_exec_t;
init_daemon_domain(simpleserver_t, simpleserver_exec_t)

#permissive simpleserver_t;

########################################
#
# simpleserver local policy
#
allow simpleserver_t self:fifo_file rw_fifo_file_perms;
allow simpleserver_t self:unix_stream_socket create_stream_socket_perms;

domain_use_interactive_fds(simpleserver_t)

files_read_etc_files(simpleserver_t)

miscfiles_read_localization(simpleserver_t)

allow simpleserver_t bin_t:file { execute execute_no_trans map };

# Authorise used of 5988 and bind on TCP socket
allow simpleserver_t self:tcp_socket { accept bind create getattr listen shutdown read write };
allow simpleserver_t node_t:tcp_socket node_bind;
allow simpleserver_t pegasus_http_port_t:tcp_socket name_bind;

# Authorise writing and reading on /var/www/html
allow simpleserver_t httpd_sys_content_t:dir { create read getattr lock search write };
allow simpleserver_t httpd_sys_content_t:file { getattr ioctl open read write};
```
simpleserver.fc
```bash
/usr/local/bin/simpleserver             --      gen_context(system_u:object_r:simpleserver_exec_t,s0)
```

simpleserver.if
```bash
```