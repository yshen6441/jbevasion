#include "hide.h"
#include "krw.h"
#include <libjailbreak/kernel.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

#define VNODE_BUF_SIZE 0x200
#define HIDE_SAVED_MAX 64

static struct {
	uint64_t vaddr;
	uint8_t  data[VNODE_BUF_SIZE];
} g_saved_vnodes[HIDE_SAVED_MAX];
static int g_saved_count = 0;

#define OFF_V_TYPE          0x074
#define OFF_V_USECOUNT      0x060
#define OFF_V_IOCOUNT       0x064

static uint64_t get_vnode_for_path(const char *path) {
	int fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) return 0;
	uint64_t vnode = krw_proc_vnode_for_fd(krw_proc_self(), fd);
	close(fd);
	return vnode;
}

int vnode_hide_init(void) { return 0; }
int vnode_hide_cleanup(void) { return 0; }

int vnode_hide_path(const char *path) {
	uint64_t vnode = get_vnode_for_path(path);
	if (!vnode) {
		fprintf(stderr, "hide: cannot resolve vnode for '%s'\n", path);
		return -1;
	}

	if (g_saved_count < HIDE_SAVED_MAX) {
		int found = 0;
		for (int i = 0; i < g_saved_count; i++) {
			if (g_saved_vnodes[i].vaddr == vnode) { found = 1; break; }
		}
		if (!found) {
			uint8_t buf[VNODE_BUF_SIZE];
			if (krw_read_buf(vnode, buf, sizeof(buf)) == 0) {
				g_saved_vnodes[g_saved_count].vaddr = vnode;
				memcpy(g_saved_vnodes[g_saved_count].data, buf, sizeof(buf));
				g_saved_count++;
			}
		}
	}

	uint8_t vbuf[VNODE_BUF_SIZE];
	memset(vbuf, 0, sizeof(vbuf));
	if (krw_read_buf(vnode, vbuf, sizeof(vbuf)) != 0) {
		fprintf(stderr, "hide: failed to read vnode\n");
		return -1;
	}

	uint16_t orig_type = *(uint16_t *)(vbuf + OFF_V_TYPE);
	*(uint16_t *)(vbuf + OFF_V_TYPE) = 0;
	*(uint32_t *)(vbuf + OFF_V_USECOUNT) = 0x2000;
	*(uint32_t *)(vbuf + OFF_V_IOCOUNT)  = 0x2000;

	if (krw_write_buf(vnode, vbuf, sizeof(vbuf)) != 0) {
		fprintf(stderr, "hide: failed to write vnode\n");
		return -1;
	}

	printf("hide: %s  vnode 0x%llx  v_type 0x%x -> VBAD\n",
	       path, (unsigned long long)vnode, orig_type);
	return 0;
}

int vnode_hide_all(void) {
	printf("hide: vnode_hide_all is deprecated, use apphide commands instead\n");
	return -1;
}

/* Restore a specific vnode by its original vaddr */
int vnode_restore_path(uint64_t vaddr) {
	for (int i = 0; i < g_saved_count; i++) {
		if (g_saved_vnodes[i].vaddr == vaddr) {
			if (krw_write_buf(vaddr, g_saved_vnodes[i].data, VNODE_BUF_SIZE) == 0) {
				printf("hide: restored vnode 0x%llx\n", (unsigned long long)vaddr);
				memmove(&g_saved_vnodes[i], &g_saved_vnodes[i+1],
				        (g_saved_count - i - 1) * sizeof(g_saved_vnodes[0]));
				g_saved_count--;
				return 0;
			}
			fprintf(stderr, "hide: failed to restore vnode 0x%llx\n", (unsigned long long)vaddr);
			return -1;
		}
	}
	fprintf(stderr, "hide: vnode 0x%llx not found in saved list\n", (unsigned long long)vaddr);
	return -1;
}

int vnode_restore_all(void) {
	int restored = 0;
	for (int i = 0; i < g_saved_count; i++) {
		if (krw_write_buf(g_saved_vnodes[i].vaddr, g_saved_vnodes[i].data, VNODE_BUF_SIZE) == 0) {
			printf("restore: OK  0x%llx\n", (unsigned long long)g_saved_vnodes[i].vaddr);
			restored++;
		} else {
			fprintf(stderr, "restore: FAILED  0x%llx\n", (unsigned long long)g_saved_vnodes[i].vaddr);
		}
	}
	g_saved_count = 0;
	return (restored > 0) ? 0 : -1;
}

int proc_platformize(uint64_t proc) {
	if (!proc) return -1;
	uint32_t csflags = krw_read32(proc + koffsetof(proc, csflags));
	csflags |= 0x04000000;
	csflags &= ~0x00000001;
	csflags &= ~0x00000002;
	krw_write32(proc + koffsetof(proc, csflags), csflags);
	return 0;
}

int proc_clean_csflags(uint64_t proc) {
	if (!proc) return -1;
	uint32_t csflags = krw_read32(proc + koffsetof(proc, csflags));
	csflags &= ~0x00000004;
	csflags &= ~0x02000000;
	csflags &= ~0x08000000;
	csflags |= 0x04000000;
	krw_write32(proc + koffsetof(proc, csflags), csflags);
	return 0;
}

int proc_platformize_pid(pid_t pid) {
	uint64_t proc = krw_proc_for_pid(pid);
	if (!proc) return -1;
	return proc_platformize(proc);
}

int proc_clean_csflags_pid(pid_t pid) {
	uint64_t proc = krw_proc_for_pid(pid);
	if (!proc) return -1;
	return proc_clean_csflags(proc);
}

int proc_hide_pid(pid_t pid) {
	uint64_t proc = krw_proc_for_pid(pid);
	if (!proc) return -1;

	proc_platformize(proc);
	proc_clean_csflags(proc);

	uint32_t p_flag = krw_read32(proc + koffsetof(proc, flag));
	p_flag &= ~0x00000100;
	krw_write32(proc + koffsetof(proc, flag), p_flag);

	uint64_t task = krw_proc_task(proc);
	if (task) {
		uint32_t task_flags = krw_read32(task + koffsetof(task, flags));
		task_flags |= 0x00000400;
		krw_write32(task + koffsetof(task, flags), task_flags);
	}

	if (koffsetof(proc_ro, exists) && koffsetof(proc_ro, csflags)) {
		uint64_t proc_ro = krw_read64(proc + koffsetof(proc, proc_ro));
		if (proc_ro) {
			uint32_t ro_csflags = krw_read32(proc_ro + koffsetof(proc_ro, csflags));
			ro_csflags |= 0x04000000;
			krw_write32(proc_ro + koffsetof(proc_ro, csflags), ro_csflags);
		}
	}
	return 0;
}

int proc_hide_self(void) {
	uint64_t proc = krw_proc_self();
	if (!proc) return -1;

	proc_platformize(proc);
	proc_clean_csflags(proc);

	uint32_t p_flag = krw_read32(proc + koffsetof(proc, flag));
	p_flag &= ~0x00000100;
	krw_write32(proc + koffsetof(proc, flag), p_flag);

	uint64_t task = krw_proc_task(proc);
	if (task) {
		uint32_t task_flags = krw_read32(task + koffsetof(task, flags));
		task_flags |= 0x00000400;
		krw_write32(task + koffsetof(task, flags), task_flags);
	}

	if (koffsetof(proc_ro, exists) && koffsetof(proc_ro, csflags)) {
		uint64_t proc_ro = krw_read64(proc + koffsetof(proc, proc_ro));
		if (proc_ro) {
			uint32_t ro_csflags = krw_read32(proc_ro + koffsetof(proc_ro, csflags));
			ro_csflags |= 0x04000000;
			krw_write32(proc_ro + koffsetof(proc_ro, csflags), ro_csflags);
		}
	}
	return 0;
}