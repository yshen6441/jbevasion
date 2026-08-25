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

#define HIDE_SAVED_MAX 64

/* Only save/restore v_type + usecount/iocount, not the full vnode struct.
 * Saving the full vnode corrupts v_name/v_parent when the file is moved
 * after marking VBAD. */
#define OFF_V_TYPE          0x074
#define OFF_V_USECOUNT      0x060
#define OFF_V_IOCOUNT       0x064

static struct {
	uint64_t vaddr;
	uint16_t orig_v_type;
	uint32_t orig_usecount;
	uint32_t orig_iocount;
} g_saved[HIDE_SAVED_MAX];
static int g_saved_count = 0;

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

	/* Check if already saved */
	for (int i = 0; i < g_saved_count; i++) {
		if (g_saved[i].vaddr == vnode) {
			printf("hide: %s already hidden\n", path);
			return 0;
		}
	}

	if (g_saved_count >= HIDE_SAVED_MAX) {
		fprintf(stderr, "hide: too many hidden paths\n");
		return -1;
	}

	uint16_t v_type = krw_read16(vnode + OFF_V_TYPE);
	uint32_t usecount = krw_read32(vnode + OFF_V_USECOUNT);
	uint32_t iocount = krw_read32(vnode + OFF_V_IOCOUNT);

	g_saved[g_saved_count].vaddr = vnode;
	g_saved[g_saved_count].orig_v_type = v_type;
	g_saved[g_saved_count].orig_usecount = usecount;
	g_saved[g_saved_count].orig_iocount = iocount;
	g_saved_count++;

	/* Set v_type = VBAD, inflate usecount/iocount to prevent recycling */
	krw_write16(vnode + OFF_V_TYPE, 0);
	krw_write32(vnode + OFF_V_USECOUNT, 0x2000);
	krw_write32(vnode + OFF_V_IOCOUNT, 0x2000);

	printf("hide: %s  vnode 0x%llx  v_type 0x%x -> VBAD\n",
	       path, (unsigned long long)vnode, v_type);
	return 0;
}

int vnode_hide_all(void) {
	printf("hide: vnode_hide_all is deprecated, use apphide commands instead\n");
	return -1;
}

int vnode_restore_path(uint64_t vaddr) {
	for (int i = 0; i < g_saved_count; i++) {
		if (g_saved[i].vaddr == vaddr) {
			krw_write16(vaddr + OFF_V_TYPE, g_saved[i].orig_v_type);
			krw_write32(vaddr + OFF_V_USECOUNT, g_saved[i].orig_usecount);
			krw_write32(vaddr + OFF_V_IOCOUNT, g_saved[i].orig_iocount);
			printf("hide: restored vnode 0x%llx v_type=0x%x\n",
			       (unsigned long long)vaddr, g_saved[i].orig_v_type);
			memmove(&g_saved[i], &g_saved[i+1],
			        (g_saved_count - i - 1) * sizeof(g_saved[0]));
			g_saved_count--;
			return 0;
		}
	}
	fprintf(stderr, "hide: vnode 0x%llx not found\n", (unsigned long long)vaddr);
	return -1;
}

int vnode_restore_all(void) {
	int restored = 0;
	for (int i = 0; i < g_saved_count; i++) {
		krw_write16(g_saved[i].vaddr + OFF_V_TYPE, g_saved[i].orig_v_type);
		krw_write32(g_saved[i].vaddr + OFF_V_USECOUNT, g_saved[i].orig_usecount);
		krw_write32(g_saved[i].vaddr + OFF_V_IOCOUNT, g_saved[i].orig_iocount);
		printf("restore: OK  0x%llx v_type=0x%x\n",
		       (unsigned long long)g_saved[i].vaddr, g_saved[i].orig_v_type);
		restored++;
	}
	g_saved_count = 0;
	return (restored > 0) ? 0 : -1;
}

/* Export the most recently hidden vnode's data. Returns the last entry from
 * g_saved[] without removing it. Used by apphide to persist vnode data to
 * marker files across process restarts. */
int vnode_export_last(uint64_t *vaddr, uint16_t *vtype, uint32_t *usecount, uint32_t *iocount) {
	if (g_saved_count == 0) return -1;
	int i = g_saved_count - 1;
	*vaddr = g_saved[i].vaddr;
	*vtype = g_saved[i].orig_v_type;
	*usecount = g_saved[i].orig_usecount;
	*iocount = g_saved[i].orig_iocount;
	return 0;
}

/* Restore a vnode from previously exported data. This is used when
 * apphide reads back the marker file entries in a new process. */
int vnode_import_and_restore(uint64_t vaddr, uint16_t vtype, uint32_t usecount, uint32_t iocount) {
	/* Verify the vnode still exists by reading its current v_type */
	uint16_t current = krw_read16(vaddr + OFF_V_TYPE);
	if (current != 0) {
		/* Not VBAD anymore — already restored */
		return 0;
	}
	krw_write16(vaddr + OFF_V_TYPE, vtype);
	krw_write32(vaddr + OFF_V_USECOUNT, usecount);
	krw_write32(vaddr + OFF_V_IOCOUNT, iocount);
	printf("restore: imported 0x%llx v_type=0x%x\n", (unsigned long long)vaddr, vtype);
	return 0;
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