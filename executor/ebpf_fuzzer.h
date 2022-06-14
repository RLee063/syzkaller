#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAGIC_VAL_CORRUPT 0x4141414141414141
#define MAGIC_VAL_STORAGE 0x4242424242424242
#define CORRUPT_MAP_SIZE (8192)
#define STORAGE_MAP_SIZE (16)
#define VALUE_MAP_SIZE (8192)
#define CORRUPT_MAP_FD 	100
#define STORAGE_MAP_FD 	101
#define VALUE_MAP_FD	102

int bpf(unsigned int cmd, union bpf_attr* attr, size_t size)
{
	return syscall(SYS_bpf, cmd, attr, size);
}

int update_corrupt_map(int fd)
{
	uint64_t key = 0;
	unsigned long buf[CORRUPT_MAP_SIZE / sizeof(long)];
	for (int i = 0; i < (int)(CORRUPT_MAP_SIZE / sizeof(long)); i++) {
		buf[i] = MAGIC_VAL_CORRUPT;
	}
	union bpf_attr attr;
	memset(&attr, 0, sizeof(bpf_attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)&key;
	attr.value = (uint64_t)&buf;

	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int update_storage_map(int fd)
{
	uint64_t key = 0;
	unsigned long buf[STORAGE_MAP_SIZE / sizeof(long)];
	for (int i = 0; i < (int)(STORAGE_MAP_SIZE / sizeof(long)); i++) {
		buf[i] = MAGIC_VAL_STORAGE;
	}
	union bpf_attr attr;
	memset(&attr, 0, sizeof(bpf_attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)&key;
	attr.value = (uint64_t)&buf;

	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
int update_value_map(int fd)
{
	uint64_t key = 0;
	unsigned long buf[VALUE_MAP_SIZE / sizeof(long)];
	for (int i = 0; i < (int)(VALUE_MAP_SIZE / sizeof(long)); i++) {
		buf[i] = 0;
	}
	union bpf_attr attr;
	memset(&attr, 0, sizeof(bpf_attr));
	attr.map_fd = fd;
	attr.key = (uint64_t)&key;
	attr.value = (uint64_t)&buf;

	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int reset_ebpf_maps(){
	return 0;
	if (update_corrupt_map(CORRUPT_MAP_FD) < 0) {
		debug("[-] update corrupt map error!\n");
		return -1;
	}
	if (update_storage_map(STORAGE_MAP_FD) < 0) {
		debug("[-] update storage map error!\n");
		return -1;
	}
	if (update_value_map(VALUE_MAP_FD) < 0) {
		debug("[-] update value map error!\n");
		return -1;
	}
	return 0;
}

int init_maps(int* corrupt_map_fd, int* storage_map_fd, int* value_map_fd)
{
	union bpf_attr corrupt_map;
	memset(&corrupt_map, 0, sizeof(bpf_attr));
	corrupt_map.map_type = BPF_MAP_TYPE_ARRAY;
	corrupt_map.key_size = 4;
	corrupt_map.value_size = CORRUPT_MAP_SIZE;
	corrupt_map.max_entries = 1;
	strcpy(corrupt_map.map_name, "corrupt_map");
	*corrupt_map_fd = (int)bpf(BPF_MAP_CREATE, &corrupt_map,
				   sizeof(corrupt_map));
	if (*corrupt_map_fd < 0) {
		debug("[-] create corrupt map error!\n");
		return -1;
	}

	union bpf_attr storage_map;
	memset(&storage_map, 0, sizeof(bpf_attr));
	storage_map.map_type = BPF_MAP_TYPE_ARRAY;
	storage_map.key_size = 4;
	storage_map.value_size = STORAGE_MAP_SIZE;
	storage_map.max_entries = 1;
	strcpy(storage_map.map_name, "storage_map");
	*storage_map_fd = (int)bpf(BPF_MAP_CREATE, &storage_map,
				   sizeof(storage_map));
	if (*storage_map_fd < 0) {
		debug("[-] create storage map error!\n");
		return -1;
	}

	union bpf_attr value_map;
	memset(&value_map, 0, sizeof(bpf_attr));
	value_map.map_type = BPF_MAP_TYPE_ARRAY;
	value_map.key_size = 4;
	value_map.value_size = VALUE_MAP_SIZE;
	value_map.max_entries = 1;
	strcpy(value_map.map_name, "value_map");
	*value_map_fd = (int)bpf(BPF_MAP_CREATE, &value_map,
				   sizeof(value_map));
	if (*value_map_fd < 0) {
		debug("[-] create value map error!\n");
		return -1;
	}

	return 0;
}

int init_ebpf_fuzzer()
{
	int corrupt_map_fd, storage_map_fd, value_map_fd;
	if (init_maps(&corrupt_map_fd, &storage_map_fd, &value_map_fd) < 0) {
		return -1;
	}
	if (dup2(corrupt_map_fd, CORRUPT_MAP_FD) < 0){
		debug("[-] dup corrupt_map_fd error!\n");
		return -1;
	}
	if (dup2(storage_map_fd, STORAGE_MAP_FD) < 0){
		debug("[-] dup storage_map_fd error!\n");
		return -1;
	}
	if (dup2(value_map_fd, VALUE_MAP_FD) < 0){
		debug("[-] dup value_map_fd error!\n");
		return -1;
	}
	close(corrupt_map_fd);
	close(storage_map_fd);
	close(value_map_fd);
	return 0;
}

#define	LISTENER_PORT		(1337)
#define	LISTENER_BACKLOG	(0x30)

int exec_prog(int prog_fd)
{
	int ret = -1;
	int socks[2] = {0};
    if(0 != socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    {
		ret = -1;
        goto done;
    }
    if(0 != setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(int)))
    {
        goto done;
    }
    if(0x7 != write(socks[1], "ch0mpie", 0x7))
    {
        goto done;
    }
    ret = 0;
done:
    close(socks[0]);
    close(socks[1]);
    return ret;
}

int lookup_map_element(int map_fd, uint64_t key, void* value)
{
    int ret = -1;
    union bpf_attr attr;
	memset(&attr, 0, sizeof(bpf_attr));
	attr.map_fd = map_fd;
	attr.key = (uint64_t)&key;
	attr.value = (uint64_t)value;

    ret = bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));

    return ret;
}

#define KERNEL_BASE                    0xFFFF000000000000
#define KERNEL_DS                      0xFFFFFFFFFFFFFFFF
#define IS_KERNEL_POINTER(x)           (((x > KERNEL_BASE) && (x < KERNEL_DS))?1:0)
uint64_t what_the_hell;
uint32_t is_complete[2];

char vals_storage[STORAGE_MAP_SIZE] = {0};
char vals_corrupt[CORRUPT_MAP_SIZE] = {0};
uint64_t needle = MAGIC_VAL_STORAGE;
int ebpf_fuzzer_check(int prog_fd){
	int ret = 0;
	return ret;
	
	what_the_hell = 0;
	is_complete[0] = 0;
	is_complete[1] = 0;

	int err = exec_prog(prog_fd);
	if (err < 0) {
		/* prog not execute successfully */
		goto done;
	}
	
	memset(vals_storage, 0, sizeof(vals_storage));
	if(0 != lookup_map_element(STORAGE_MAP_FD, 0, vals_storage))
    {
        debug("[-] failed to retrieve storage map element!\n");
		goto done;
    }
	// memcpy(&what_the_hell, &vals[sizeof(uint64_t)], sizeof(uint64_t));
	memcpy(&is_complete, vals_storage+8, sizeof(uint64_t));
	if (is_complete[0] != 0xdeadbeef || is_complete[1] != 0xbabecafe){
		debug("[-] insn may exit before try_vuls get executed... :(\n");
		goto done;
	}else{
		debug("[+] wow it really executed try_vuls, lets take a look at the result :)\n");
	}

	memcpy(&what_the_hell, vals_storage, sizeof(uint64_t));

	if(what_the_hell != MAGIC_VAL_STORAGE &&
		what_the_hell != MAGIC_VAL_CORRUPT)
    {
		if (IS_KERNEL_POINTER(what_the_hell)){
			debug("[+] executor detected leaked %lx\n", what_the_hell);
			ret = kBPFLeakStatus;
			goto done;
		}
		debug("[+] executor detected oob read\n");
		ret = kBPFOOBReadStatus;
		goto done;
    }

	if (what_the_hell != MAGIC_VAL_STORAGE){ //oob_read done.
		if (what_the_hell != MAGIC_VAL_CORRUPT){
			if (IS_KERNEL_POINTER(what_the_hell)){
				debug("[+] executor detected leaked %lx\n", what_the_hell);
				ret = kBPFLeakStatus;
				goto done;
			}
			else{
				debug("[+] executor detected oob read\n");
				ret = kBPFOOBReadStatus;
				goto done;
			}
		}
		// indicate what_the_hell == MAGIC_VAL_CORRUPT, so that try_oob_read failed...
		goto done;
	} else{
		if(0 != lookup_map_element(CORRUPT_MAP_FD, 0, vals_corrupt))
		{
			debug("[-] failed to retrieve storage map element!\n");
			goto done;
		}

		if(!memmem(vals_corrupt, CORRUPT_MAP_SIZE, &needle, sizeof(needle))){
			debug("[+] executor detected oob write\n");
			ret = kBPFOOBWriteStatus;
			goto done;
		}
		
		goto done;
	}
done:
	close(prog_fd);
	return ret;
}