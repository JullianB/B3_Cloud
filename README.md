### 1. Prise en main

#### Manipulation du conteneur:

- conteneur actif: -> docker ps
```
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
b80e7d117a63        alpine              "sleep 99999"       5 seconds ago       Up 4 seconds                            wonderful_tu
```

- Supprimer le container:
```
$ docker rm happy_archimedes
happy_archimedes
```
-----


#### Montrer que le conteneur utilise :

- Une arborescence de processus différente:
( Machine hôte )
```
[kraken@localhost ~]$ ps -ef | head
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 15:01 ?        00:00:01 /usr/lib/systemd/systemd --switched-root --system --deserialize 22
root         2     0  0 15:01 ?        00:00:00 [kthreadd]
root         3     2  0 15:01 ?        00:00:00 [kworker/0:0]
root         4     2  0 15:01 ?        00:00:00 [kworker/0:0H]
root         5     2  0 15:01 ?        00:00:00 [kworker/u2:0]
root         6     2  0 15:01 ?        00:00:00 [ksoftirqd/0]
root         7     2  0 15:01 ?        00:00:00 [migration/0]
root         8     2  0 15:01 ?        00:00:00 [rcu_bh]
root         9     2  0 15:01 ?        00:00:00 [rcu_sched]
```

( Conteneur )
```
/ # ps -ef | head
PID   USER     TIME  COMMAND
    1 root      0:00 sleep 9999
    6 root      0:00 sh
   14 root      0:00 ps -ef
```

- Des cartes réseau différentes:
```
[kraken@localhost ~]$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:38:01:57 brd ff:ff:ff:ff:ff:ff
    inet 192.168.181.153/28 brd 192.168.181.159 scope global noprefixroute dynamic eth0
       valid_lft 86240sec preferred_lft 86240sec
    inet6 fe80::773c:1954:51e:4fff/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:38:01:58 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.51/24 brd 10.10.10.255 scope global noprefixroute eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::215:5dff:fe38:158/64 scope link
       valid_lft forever preferred_lft forever
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:8c:c5:83:54 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:8cff:fec5:8354/64 scope link
       valid_lft forever preferred_lft forever
6: vethf9fbc5a@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default
    link/ether 2e:1c:b8:a3:a6:f2 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::2c1c:b8ff:fea3:a6f2/64 scope link
       valid_lft forever preferred_lft forever
``` 

- Des utilisateurs système différents:
( Machine hôte )
```
[kraken@localhost ~]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
kraken:x:1000:1000:kraken:/home/kraken:/bin/bash
```

( Conteneur )
```
/ # cat /etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
```

- Des points de montage différents:
( Machine hôte )
```
[kraken@localhost ~]$ df
Filesystem              1K-blocks    Used Available Use% Mounted on
devtmpfs                   896508       0    896508   0% /dev
tmpfs                      908260       0    908260   0% /dev/shm
tmpfs                      908260    9260    899000   2% /run
tmpfs                      908260       0    908260   0% /sys/fs/cgroup
/dev/mapper/centos-root  33529860 2229972  31299888   7% /
/dev/sda1                 1038336  151744    886592  15% /boot
tmpfs                      181652       0    181652   0% /run/user/1000
```

( Conteneur )
```
/ # df
Filesystem           1K-blocks      Used Available Use% Mounted on
overlay               33529860   2229976  31299884   7% /
tmpfs                    65536         0     65536   0% /dev
tmpfs                   908260         0    908260   0% /sys/fs/cgroup
shm                      65536         0     65536   0% /dev/shm
/dev/mapper/centos-root
                      33529860   2229976  31299884   7% /etc/resolv.conf
/dev/mapper/centos-root
                      33529860   2229976  31299884   7% /etc/hostname
/dev/mapper/centos-root
                      33529860   2229976  31299884   7% /etc/hosts
tmpfs                   908260         0    908260   0% /proc/acpi
tmpfs                    65536         0     65536   0% /proc/kcore
tmpfs                    65536         0     65536   0% /proc/keys
tmpfs                    65536         0     65536   0% /proc/timer_list
tmpfs                    65536         0     65536   0% /proc/timer_stats
tmpfs                    65536         0     65536   0% /proc/sched_debug
tmpfs                   908260         0    908260   0% /proc/scsi
tmpfs                   908260         0    908260   0% /sys/firmware
```

#### Lancer un conteneur NGINX

- Utiliser l'image nginx et partager un port de l'hôte vers le port 80:
```
[kraken@localhost ~]$ sudo docker run -d -p 80:80 nginx
b2604cabf239829b00161d1e5be5d0796e74c56918f78c24ce800c8a4da36c45
[kraken@localhost ~]$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                NAMES
b2604cabf239        nginx               "nginx -g 'daemon of…"   10 seconds ago      Up 8 seconds        0.0.0.0:80->80/tcp   peaceful_clarke
```

- Visiter le service web:
```
[kraken@localhost ~]$ curl localhost
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

----

### 2. Gestion d'images

- récupérer une image de Apache en version 2.2 et la lancer en partageant un port qui permet d'accéder à la page d'accueil d'Apache
( # docker pull httpd:2.2 )
```
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
httpd               2.2                 e06c3dbbfe23        23 months ago       171MB
```
```
[kraken@localhost ~]$ docker run -d -p 80:80 httpd:2.2
099db4daab7e9489a66be8430a06c63dd96af66587c8133136ea5854bf6c5d85
```

#### Créer une image qui lance un serveur web python

```
FROM alpine:latest

RUN apk update && apk add python3
WORKDIR ./app
COPY index.html .
CMD ["python3", "-m", "http.server", "8888"]
EXPOSE 8888
```

#### Lancer le conteneur et accéder au serveur web du conteneur depuis votre PC:
```
[kraken@localhost tp1]$ sudo docker run -d -p 8888:8888 pyalpine
df9aae958fbcd65c752548763d421f1c8550c81d82701044bd2d0a67efb03a64
```
#### - Utiliser l'option -v

```
[kraken@localhost tp1]$ sudo docker run -d -p 8888:8888 -v "test:/app/test" pyalpine
9fb685b320a84a7096d6811cf0de6fd80f60ceb8c57e40e5e1360926b56dbf71
```

### 3. Manipulation du démon docker

#### Modifier le socket utilisé pour la communication avec le démon Docker
( VM 1 )
```
    [root@localhost ~]# dockerd -H tcp://10.10.10.52
    [root@localhost ~]# firewall-cmd --add-port=2375/tcp
```
( VM 2)
```
[root@localhost ~]# docker -H tcp://10.10.10.52:2375 ps -a
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    ccd457o0f5e3        d983ks3fp4h9        "python3 -m http.ser…"   11 minutes ago      Exited (137) 3 minutes ago                       peaceful_clarke
    ```
```
- Dans le fichier `/etc/docker/daemon.json` :
```json
{
"data-root": "/data/docker"
}
```

( VM 2 )
```
[root@localhost ~]# docker -H tcp://10.10.10.52:2375 run -p 8888:8888 -d d983ks3fp4h9
[root@localhost ~]# docker -H tcp://10.10.10.52:2375 ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                    NAMES
b23943ce587f        d983ks3fp4h9        "python3 -m http.ser…"   24 seconds ago      Up 30 seconds       0.0.0.0:8888->8888/tcp   loving_elbakyan
```


### 4. Docker-compose

#### Ecrire un docker-compose-v1.yml:

```yml
version: '3.3'

services:
  node:
    build: .
    restart: on-failure
    ports:
      - "8888:8888"
```

#### Ajouter un deuxième conteneur docker-compose-v2.yml

```yml
version: '3.3'

services:
  web:
    build: ./web/
    restart: on-failure
    expose:
      - "8888"
    networks:
      nginx-net:
        aliases:
          - python

  proxy:
    image: nginx
    networks:
      - nginx-net
    volumes:
      - ./nginx/conf:/etc/nginx/conf.d
      - ./nginx/certif:/certif
    depends_on:
      - web
      ports:
      - "443:443"

networks:
  nginx-net:
```

#### Conteneuriser une application donnée

```yml
version: '3.3'

services:
  web:
    build: ./web/
    restart: on-failure
    networks:
      internal:
        aliases:
          - python
    depends_on:
      - redis

  nginx:
    image: nginx
    networks:
      - internal
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./nginx/certif:/certif
    depends_on:
      - web
      - redis
    ports:
      - "443:443"

  redis:
    image: redis
    networks:
      internal:
        aliases:
          - db
    expose:
      - "6379"

networks:
  internal:
```