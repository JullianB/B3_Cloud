## I. Gestion de conteneurs Docker

### - 🌞 Mettre en évidence l'utilisation de chacun des processus liés à Docker :

```bash
[kraken@localhost etc]$ systemctl status docker | grep -A 3 "CGroup"
   CGroup: /system.slice/docker.service
           └─3808 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
```
 - dockerd lance containerd mais n'est pas son parent
```
[kraken@localhost ~]$ ps -ely | grep containerd
S     0  1207     1  0  80   0 39512 139286 futex_ ?       00:00:00 containerd
S     0  2032  1207  0  80   0 10852 26921 futex_ ?        00:00:00 containerd-shim

```
- containerd est le parent de containerd-shim

### - 🌞 Utiliser l'API HTTP mise à disposition par dockerd :
- récupérer la liste des conteneurs
- récupérer la liste des images disponibles

```json
[kraken@localhost ~]$ curl --unix-socket /var/run/docker.sock http://localhost/images/json
[{"Containers":-1,"Created":1578413067,"Id":"sha256:f96c2a7048419b6031336a45a3f5e93d7303e890796669fec378ee395638fd07","Labels":null,"ParentId":"sha256:8c37282631f9c885ab760842d6e8ac338e1becbcd4422cf0c20a16b54faf5940","RepoDigests":null,"RepoTags":["tp1_web:latest"],"SharedSize":-1,"Size":62121626,"VirtualSize":62121626},{"Containers":-1,"Created":1578397091,"Id":"sha256:9ead7233af751a1cd03138fd14d32c496b7c3c1673797c667263aebce3ecc19a","Labels":null,"ParentId":"sha256:2e973654e5689ffa0a57792b57d92746dc96b8b033aa973b72973e67bf9e8dfb","RepoDigests":null,"RepoTags":["pyalpine:latest"],"SharedSize":-1,"Size":62121626,"VirtualSize":62121626},{"Containers":-1,"Created":1578014955,"Id":"sha256:9b188f5fb1e6e1c7b10045585cb386892b2b4e1d31d62e3688c6fa8bf9fd32b5","Labels":null,"ParentId":"","RepoDigests":["redis@sha256:90d44d431229683cadd75274e6fcb22c3e0396d149a8f8b7da9925021ee75c30"],"RepoTags":["redis:latest"],"SharedSize":-1,"Size":98205111,"VirtualSize":98205111},{"Containers":-1,"Created":1577546421,"Id":"sha256:f7bb5701a33c0e572ed06ca554edca1bee96cbbc1f76f3b01c985de7e19d0657","Labels":{"maintainer":"NGINX Docker Maintainers <docker-maint@nginx.com>"},"ParentId":"","RepoDigests":["nginx@sha256:b2d89d0a210398b4d1120b3e3a7672c16a4ba09c2c4a0395f18b9f7999b768f2"],"RepoTags":["nginx:latest"],"SharedSize":-1,"Size":126323778,"VirtualSize":126323778},{"Containers":-1,"Created":1577215212,"Id":"sha256:cc0abc535e36a7ede71978ba2bbd8159b8a5420b91f2fbc520cdf5f673640a34","Labels":null,"ParentId":"","RepoDigests":["alpine@sha256:2171658620155679240babee0a7714f6509fae66898db422ad803b951257db78"],"RepoTags":["alpine:latest"],"SharedSize":-1,"Size":5591300,"VirtualSize":5591300},{"Containers":-1,"Created":1516317158,"Id":"sha256:e06c3dbbfe239c6fca50b6ab6935b3122930fa2eea2136979e5b46ad77ecb685","Labels":null,"ParentId":"","RepoDigests":["httpd@sha256:9784d70c8ea466fabd52b0bc8cde84980324f9612380d22fbad2151df9a430eb"],"RepoTags":["httpd:2.2"],"SharedSize":-1,"Size":171293537,"VirtualSize":171293537}]
```

```json
[kraken@localhost ~]$ curl --unix-socket /var/run/docker.sock http://localhost/containers/json
[{"Id":"46c0abacf9612548de735d71696d3a37e83814f0ba0f3a72d0816aa92d7a08c0","Names":["/zen_kare"],"Image":"alpine","ImageID":"sha256:cc0abc535e36a7ede71978ba2bbd8159b8a5420b91f2fbc520cdf5f673640a34","Command":"sleep 9999","Created":1579198099,"Ports":[],"Labels":{},"State":"running","Status":"Up 29 minutes","HostConfig":{"NetworkMode":"default"},"NetworkSettings":{"Networks":{"bridge":{"IPAMConfig":null,"Links":null,"Aliases":null,"NetworkID":"46b3d0455c797ee843851bd895cc1e7d75a22b652daad9a1f519871e9be27f7b","EndpointID":"11ea235815317f2f17c3508e80ec30e15fbbabce8b2f622fc98c330ff0f93721","Gateway":"172.17.0.1","IPAddress":"172.17.0.2","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"MacAddress":"02:42:ac:11:00:02","DriverOpts":null}}},"Mounts":[]}]
```
----
## 1. Namespaces

### - 🌞 Trouver les namespaces utilisés par votre shell :

```
[kraken@localhost ~]$ ps
  PID TTY          TIME CMD
 1949 pts/0    00:00:00 bash
 2417 pts/0    00:00:00 ps
[kraken@localhost ~]$ ls -al /proc/1949/ns
total 0
dr-x--x--x. 2 kraken kraken 0 16 janv. 19:44 .
dr-xr-xr-x. 9 kraken kraken 0 16 janv. 19:03 ..
lrwxrwxrwx. 1 kraken kraken 0 16 janv. 19:44 ipc -> ipc:[4026531839]
lrwxrwxrwx. 1 kraken kraken 0 16 janv. 19:44 mnt -> mnt:[4026531840]
lrwxrwxrwx. 1 kraken kraken 0 16 janv. 19:44 net -> net:[4026531956]
lrwxrwxrwx. 1 kraken kraken 0 16 janv. 19:44 pid -> pid:[4026531836]
lrwxrwxrwx. 1 kraken kraken 0 16 janv. 19:44 user -> user:[4026531837]
lrwxrwxrwx. 1 kraken kraken 0 16 janv. 19:44 uts -> uts:[4026531838]
```
### - 🌞 Créer un pseudo-conteneur à la main en utilisant unshare

```
[kraken@localhost ~]$ sudo unshare --fork --pid --mount-proc sh
sh-4.2# ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0 115416  1684 pts/0    S    10:52   0:00 sh
root         2  0.0  0.0 155344  1744 pts/0    R+   10:52   0:00 ps aux
```

### - 🌞 Utiliser nsenter pour rentrer dans les namespaces de votre conteneur en y exécutant un shell
- prouver que vous êtes isolé en terme de réseau, arborescence de processus, points de montage

```
[kraken@localhost ~]$ ps -ef | grep sleep
root      2125  2109  0 11:28 ?        00:00:00 sleep 9999
kraken    2499  2076  0 11:50 pts/0    00:00:00 grep --color=auto sleep
-----
[kraken@localhost ~]$ sudo nsenter --net --target 2125 /bin/bash
[sudo] password for kraken:
[root@localhost kraken]# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
[root@localhost kraken]#
```
### E. Et alors, les namespaces User ?
#### -🌞 Mettez en place la configuration nécessaire pour que Docker utilise les namespaces de type User.

```bash
[kraken@localhost etc]$ cat /etc/subuid
kraken:10000:65555
[kraken@localhost etc]$ cat /etc/subgid
kraken:10000:65555
[kraken@localhost etc]$ sudo dockerd --userns-remap=kraken
INFO[2020-01-27T13:31:09.200080707+01:00] Starting up
INFO[2020-01-27T13:31:09.200775799+01:00] User namespaces: ID ranges will be mapped to subuid/subgid ranges of: kraken:kraken
INFO[2020-01-27T13:31:09.201997625+01:00] User namespaces: ID ranges will be mapped to subuid/subgid ranges of: kraken:kraken
INFO[2020-01-27T13:31:09.202946226+01:00] parsed scheme: "unix"                         module=grpc
INFO[2020-01-27T13:31:09.202979919+01:00] scheme "unix" not registered, fallback to default scheme  module=grpc
INFO[2020-01-27T13:31:09.203014045+01:00] ccResolverWrapper: sending update to cc: {[{unix:///run/containerd/containerd.sock 0  <nil>}] <nil>}  module=grpc
INFO[2020-01-27T13:31:09.203025529+01:00] ClientConn switching balancer to "pick_first"  module=grpc
INFO[2020-01-27T13:31:09.208047066+01:00] parsed scheme: "unix"                         module=grpc
INFO[2020-01-27T13:31:09.208100693+01:00] scheme "unix" not registered, fallback to default scheme  module=grpc
INFO[2020-01-27T13:31:09.208124852+01:00] ccResolverWrapper: sending update to cc: {[{unix:///run/containerd/containerd.sock 0  <nil>}] <nil>}  module=grpc
INFO[2020-01-27T13:31:09.208138503+01:00] ClientConn switching balancer to "pick_first"  module=grpc
INFO[2020-01-27T13:31:09.296592250+01:00] Loading containers: start.
INFO[2020-01-27T13:31:09.645028190+01:00] Default bridge (docker0) is assigned with an IP address 172.17.0.0/16. Daemon option --bip can be used to set a preferred IP address
INFO[2020-01-27T13:31:09.860268419+01:00] Loading containers: done.
INFO[2020-01-27T13:31:09.883370351+01:00] Docker daemon                                 commit=633a0ea graphdriver(s)=overlay2 version=19.03.5
INFO[2020-01-27T13:31:09.883615518+01:00] Daemon has completed initialization
INFO[2020-01-27T13:31:09.979763374+01:00] API listen on /var/run/docker.sock
```



### - 🌞 lancer un conteneur simple
### - 🌞 vérifier le réseau du conteneur

```
[kraken@localhost ~]$ docker inspect frosty_feynman
[...]
"SandboxKey": "/var/run/docker/netns/bca2a2446b06",
            "SecondaryIPAddresses": null,
            "SecondaryIPv6Addresses": null,
            "EndpointID": "6fb38b382ddefba8e5184860b4baf92bbcd2e35d7aaf7f9735020a7763c0afdb",
            "Gateway": "172.17.0.1",
            "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0,
            "IPAddress": "172.17.0.2",
            "IPPrefixLen": 16,
            "IPv6Gateway": "",
            "MacAddress": "02:42:ac:11:00:02",
[...]

```

### - 🌞 vérifier le réseau sur l'hôte
- vérifier qu'il existe une première carte réseau qui porte une IP dans le même réseau que le conteneur
- vérifier qu'il existe une deuxième carte réseau, qui est la deuxième interface de la veth pair

```
[kraken@localhost ~]$ ip a
[...]
5: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:10:fc:37:1c brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:10ff:fefc:371c/64 scope link
       valid_lft forever preferred_lft forever
7: vethd712ef6@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default
    link/ether be:ea:c4:8a:75:ca brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::bcea:c4ff:fe8a:75ca/64 scope link
       valid_lft forever preferred_lft forever
```

 - identifier les règles iptables liées à la création de votre conteneur
```
[kraken@localhost etc]$ sudo iptables -L | grep -e "chain DOCKER" -e "172.17.0.2"
ACCEPT     tcp  --  anywhere             172.17.0.2           tcp dpt:cbt
```
----
## 2. Cgroups
#### -🌞 Lancer un conteneur Docker et déduire dans quel cgroup il s'exécute

 ```
 [kraken@localhost etc]$ ps -ef | grep sleep
root      4781  4764  0 13:45 ?        00:00:00 sleep 99999
kraken    4849  2076  0 13:47 pts/0    00:00:00 grep --color=auto sleep
[kraken@localhost etc]$ cat /proc/4781/cgroup
11:perf_event:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
10:memory:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
9:blkio:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
8:net_prio,net_cls:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
7:devices:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
6:hugetlb:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
5:pids:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
4:freezer:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
3:cpuacct,cpu:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
2:cpuset:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
1:name=systemd:/docker/182f4e57d3d5429945cf71d99935cd0ada9ec2b580a39168b86923dbdd3d31e5
 ```

#### - 🌞 Lancer un conteneur Docker et trouver
- la mémoire RAM max qui lui est autorisée
- le nombre de processus qu'il peut contenir

```
[kraken@localhost etc]$ cd /sys/fs/cgroup/memory
[kraken@localhost memory]$ cat docker/memory.max_usage_in_bytes
13848576
```
```
[kraken@localhost f1506c609c518aca5834b258e57e6a7bd2ff5658d15e6afd99e3e3f10e641521]$ cat pids.max
max
```
#### - 🌞 Altérer les valeurs cgroups allouées par défaut avec des options de la commandes docker run (au moins 3)
- préciser les options utilisées
- prouver en regardant dans /sys qu'elles sont utilisées
```
-> container par defaut :
[kraken@localhost f1506c609c518aca5834b258e57e6a7bd2ff5658d15e6afd99e3e3f10e641521]$ cat pids.max
max
[kraken@localhost f1506c609c518aca5834b258e57e6a7bd2ff5658d15e6afd99e3e3f10e641521]$ cat memory.limit_in_bytes
9223372036854771712

-> container modifié :
[kraken@localhost docker]$ docker run -d -m 10m --pids-limit 10 debian sleep 99999
a89fe3cfe1d2fb20b3369cd770fbb03e6afc154d4d0cb7ea8b9f504cb3c52e69
[kraken@localhost a89fe3cfe1d2fb20b3369cd770fbb03e6afc154d4d0cb7ea8b9f504cb3c52e69]$ cat pids.max
10
[kraken@localhost a89fe3cfe1d2fb20b3369cd770fbb03e6afc154d4d0cb7ea8b9f504cb3c52e69]$ cat memory.limit_in_bytes
10485760
```
----
## 3. Capabilities

#### - 🌞 déterminer les capabilities actuellement utilisées par votre shell
```
[kraken@localhost cgroup]$ capsh --print | grep "Bounding set"
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,35,36
```
#### - 🌞 Déterminer les capabilities du processus lancé par un conteneur Docker
```
[kraken@localhost cgroup]$ ps -ef | grep sleep
root      5493  5477  0 15:22 ?        00:00:00 sleep 99999
[kraken@localhost cgroup]$ cat /proc/5493/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
[kraken@localhost cgroup]$ sudo capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
#### - 🌞 Jouer avec ping
- trouver le chemin absolu de ping
- récupérer la liste de ses capabilities
- enlever toutes les capabilities
   - en utilisant une liste vide
   - setcap '' <PATH>
- vérifier que ping ne fonctionne plus
- vérifier avec strace que c'est bien l'accès à l'ICMP qui a été enlevé
   - NB : vous devrez aussi ajouter des capa à strace pour que son ping puisse en hériter !

```
[kraken@localhost cgroup]$ getcap /usr/bin/ping
/usr/bin/ping = cap_net_admin,cap_net_raw+p

[kraken@localhost cgroup]$ sudo setcap -r /usr/bin/ping
[kraken@localhost cgroup]$ getcap /usr/bin/ping

[kraken@localhost cgroup]$ ping 10.10.10.51
ping: socket: Operation not permitted

[kraken@localhost cgroup]$ strace ping 8.8.8.8
[...]
socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = -1 EACCES (Permission denied)
socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = -1 EPERM (Operation not permitted)
[...]


```