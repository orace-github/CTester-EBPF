## test examples localy

```
docker run --mount type=bind,source=/var/www/html/inginious_courses/cours-de-c/ctesterebpf/,destination=/home/ -it ingi/inginious-c-default bash

sudo docker run --mount type=bind,source=/home/emery/Documents/2021/projets/CTester-EBPF,destination=/home/ -it ingi/inginious-c-default bash
```


## Build inginious containers

```
sudo docker build -t ingi/inginious-c-default --label="org.inginious.grading.agent_version=3" INGInious/base-containers/default/

```

## Fix setrlimit issues
```
sudo docker run --privileged  --mount type=bind,source=/home/emery/Documents/2021/projets/ctester/,destination=/home/ -it ingi/inginious-c-default bash
```

## Fix failed to attach BPF prog

```
mount -t debugfs none /sys/kernel/debug
```

## TODO

reste à déployer son propre kernel dans un  runtime kata
