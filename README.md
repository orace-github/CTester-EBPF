
# pre-requisites

```bash
sudo apt install libelf-dev libbpf-dev libseccomp-dev
```
# CTESTER-EBPF
CTester implementation with eBPF 

# Build
```bash
git clone --recursive git@github.com:oracegit/CTester-EBPF.git
cd CTester-EBPF/src
make
```
## Build libctester static file
``` bash
cd ../CTesterLib
make all
```

# Running
## Start loader
``` bash
cd ../src
sudo ./ctester
```
## Compile a test program
``` bash
cd ../test
gcc test.c ../CTesterLib/libctester.a -o test
```
## Execute
``` bash
./test
```

# How it works:

Here are the uprobe commands function
```C
// Register a process to monitor
int ctester_add_process(process_t* p, unsigned int fs_flags, long* ret_p){};
// Remove process from monitoring
int ctester_rm_process(process_t* p, fs_wrap_stats_t* fs, long* ret_p){};

```

# Aknowledgements
- [@williballenthin](https://twitter.com/williballenthin) for the idea!
- [Libpf-Bootstrap](https://github.com/libbpf/libbpf-bootstrap) team


# Other repository related on this project
- git@github.com:akemery/CTester.git
