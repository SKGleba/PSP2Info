#include <stdio.h>
#include <string.h>
#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <inttypes.h>
#include <psp2kern/io/fcntl.h>

#define LOG(...) \
	do { \
		char buffer[256]; \
		snprintf(buffer, sizeof(buffer), ##__VA_ARGS__); \
		logg(buffer, strlen(buffer), "ux0:data/vinfo.txt", 2); \
} while (0)
	
#define DMP(name, addr, size) \
	do { \
		LOG("\n- raw %s, %d\n", name, size); \
		hex_dump_log(addr, size); \
		LOG("- end\n", name, size); \
} while (0)
	
#define LOG_START(...) \
	do { \
		char buffer[256]; \
		snprintf(buffer, sizeof(buffer), ##__VA_ARGS__); \
		logg(buffer, strlen(buffer), "ux0:data/vinfo.txt", 1); \
} while (0)

#define ARRAYSIZE(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))
	
static int (* get_sysroot)() = NULL;
static int (* get_soc_rev)() = NULL;

static int logg(void *buffer, int length, const char* logloc, int create)
{
	int fd;
	if (create == 0) {
		fd = ksceIoOpen(logloc, SCE_O_WRONLY | SCE_O_APPEND, 6);
	} else if (create == 1) {
		fd = ksceIoOpen(logloc, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 6);
	} else if (create == 2) {
		fd = ksceIoOpen(logloc, SCE_O_WRONLY | SCE_O_APPEND | SCE_O_CREAT, 6);
	}
	if (fd < 0)
		return 0;

	ksceIoWrite(fd, buffer, length);
	ksceIoClose(fd);
	return 1;
}

typedef struct {
	uint32_t off;
	uint32_t sz;
	uint8_t code;
	uint8_t type;
	uint8_t active;
	uint32_t flags;
	uint16_t unk;
} __attribute__((packed)) partition_t;

typedef struct {
	char magic[0x20];
	uint32_t version;
	uint32_t device_size;
	char unk1[0x28];
	partition_t partitions[0x10];
	char unk2[0x5e];
	char unk3[0x10 * 4];
	uint16_t sig;
} __attribute__((packed)) master_block_t;

const char *part_code(int code) {
	static char *codes[] = {
		"empty",
		"idstorage",
		"slb2",
		"os0",
		"vs0",
		"vd0",
		"tm0",
		"ur0",
		"ux0",
		"gro0",
		"grw0",
		"ud0",
		"sa0",
		"mediaid",
		"pd0",
		"unused"
	};
	return codes[code];
}

const char *part_type(int type) {
	if (type == 6)
		return "FAT16";
	else if (type == 7)
		return "exFAT";
	else if (type == 0xDA)
		return "raw";
	return "unknown";
}

static int ex(const char* filloc){
  int fd;
  fd = ksceIoOpen(filloc, SCE_O_RDONLY, 0777);
  if (fd < 0) return 0;
  ksceIoClose(fd); return 1;
}

static int hex_dump_log(const char *addr, unsigned int size)
{
    unsigned int i;
    for (i = 0; i < (size >> 4); i++)
    {
        LOG(" %d: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", i, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
        addr += 0x10;
    }
    return 0;
}

// ty flow
void firmware_string(char string[8], unsigned int version) {
  char a = (version >> 24) & 0xf;
  char b = (version >> 20) & 0xf;
  char c = (version >> 16) & 0xf;
  char d = (version >> 12) & 0xf;

  memset(string, 0, 8);
  string[0] = '0' + a;
  string[1] = '.';
  string[2] = '0' + b;
  string[3] = '0' + c;
  string[4] = '\0';

  if (d) {
    string[4] = '0' + d;
    string[5] = '\0';
  }
}

int siofix(void *func) {
	int ret = 0;
	int res = 0;
	int uid = 0;
	ret = uid = ksceKernelCreateThread("siofix", func, 64, 0x10000, 0, 0, 0);
	if (ret < 0){ret = -1; goto cleanup;}
	if ((ret = ksceKernelStartThread(uid, 0, NULL)) < 0) {ret = -1; goto cleanup;}
	if ((ret = ksceKernelWaitThreadEnd(uid, &res, NULL)) < 0) {ret = -1; goto cleanup;}
	ret = res;
cleanup:
	if (uid > 0) ksceKernelDeleteThread(uid);
	return ret;
}

static int get_fc(void) {
	tai_module_info_t info;
	info.size = sizeof(tai_module_info_t);
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSysmem", &info) < 0)
		return -1;
	module_get_offset(KERNEL_PID, info.modid, 0, 0x1f821, (uintptr_t *)&get_sysroot);
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceLowio", &info) < 0)
		return -1;
	module_get_offset(KERNEL_PID, info.modid, 0, 0x3A5, (uintptr_t *)&get_soc_rev);
	return 0;
}

void logNfoPDev(master_block_t *master, const char* target) {
	if (strncmp(master->magic, "Sony Computer Entertainment Inc.", 0x20) == 0) {
		LOG("\n%s info:", target);
		LOG("\n Magic: \"%s\"", master->magic);
		LOG("\n Size: 0x%lX blocks", master->device_size);
		LOG("\n Block size: %d bytes", 512); // Always
		uint64_t szf = master->device_size;
		szf = (szf * 512) / 1024;
		master->device_size = szf / 1024;
		LOG("\n Converted size: %dMB", master->device_size);
		LOG("\n%s partitions:", target);
		for (size_t i = 0; i < ARRAYSIZE(master->partitions); ++i) {
			partition_t *p = &master->partitions[i];
			if (p->code != 0) LOG("\n %s %s %s @0x%lX - 0x%lX flags: 0x%lX", part_type(p->type), part_code(p->code), (p->active != 0) ? "Active" : "Inactive", p->off, p->off + p->sz, p->flags);
		}
		LOG("\n");
	} else
		LOG("\n%s is NOT a SCE device!\n", target);
}

int logdev(void) {
	static master_block_t master;
	int fd = ksceIoOpen("sdstor0:int-lp-act-entire", SCE_O_RDONLY, 0);
	ksceIoRead(fd, &master, sizeof(master));
	ksceIoClose(fd);	
	logNfoPDev(&master, "EMMC");
	fd = ksceIoOpen("sdstor0:mcd-lp-act-entire", SCE_O_RDONLY, 0);
	if (fd >= 0) {
		ksceIoRead(fd, &master, sizeof(master));
		ksceIoClose(fd);	
		logNfoPDev(&master, "MCD");
	}
	fd = ksceIoOpen("sdstor0:ext-lp-act-entire", SCE_O_RDONLY, 0);
	if (fd >= 0) {
		ksceIoRead(fd, &master, sizeof(master));
		ksceIoClose(fd);	
		logNfoPDev(&master, "GCD");
	}
	return 0;
}

void logNfoBattery(void) {
	unsigned int fwinfo, dfinfo;
	unsigned long long int hwinfo;
	ksceSysconGetBatteryVersion(&hwinfo, &fwinfo, &dfinfo);
	LOG("%s info:", "Battery Controller");
	LOG("\n Name: %s", ((unsigned int)hwinfo > 7) ? "Abby" : "Bert");
	LOG("\n Support reset cmd: %s", ((unsigned int)hwinfo < 0xff00) ? "Yes" : "No");
	LOG("\n HW: 0x%x", (unsigned int)hwinfo);
	LOG("\n FW: 0x%x", fwinfo);
	LOG("\n DF: 0x%x", dfinfo);
	LOG("\n ID: 0x%llx\n", hwinfo);
	
}

void logRawQas(void) {
	int kbl_param = *(unsigned int *)(get_sysroot() + 0x6c);
	DMP("QA Flags", (char *)(kbl_param + 0x20), 0x10);
	DMP("Boot Flags", (char *)(kbl_param + 0x30), 0x10);
	DMP("dip switches", (char *)(kbl_param + 0x40), 0x20);
}

void logNfoQa(void) {
	int kbl_param = *(unsigned int *)(get_sysroot() + 0x6c);
	LOG("\n\n%s info:", "QA");
	LOG("\n Release check mode: %s", (ksceKernelCheckDipsw(159) != 0) ? "Development" : "Release");
	LOG("\n PS TV emulation: %s", (ksceKernelCheckDipsw(152) != 0) ? "On" : "Off");
	LOG("\n Secure state bit: 0x%X", ((*(unsigned int *)(get_sysroot() + 0x28) ^ 1) & 1));
	LOG("\n Manufacturing mode: %s", ((*(uint32_t *)(kbl_param + 0x6C) & 0x4) != 0) ? "Yes" : "No");
	LOG("\n Mount GC-SD as sd0: %s", ((*(uint32_t *)(kbl_param + 0x6C) & 0x40000) != 0) ? "Yes" : "No");
	LOG("\n Use QA (blank) PSID: %s\n\n", (*(uint32_t *)(kbl_param + 0x4C) == 0) ? "Yes" : "No");
}

void logNfoMain(void) {
	int kbl_param = *(unsigned int *)(get_sysroot() + 0x6c);
	char cur_fw[8], min_fw[8];
	firmware_string(cur_fw, *(uint32_t *)(*(int *)(get_sysroot() + 0x6c) + 4));
	firmware_string(min_fw, *(uint32_t *)(kbl_param + 8));
	LOG("%s info:", "Console");
	LOG("\n SoC rev: %X.%01X", (get_soc_rev() << 0xf) >> 0x13, get_soc_rev() & 0xf);
	LOG("\n Cur firmware: %s", cur_fw);
	LOG("\n Min firmware: %s", min_fw);
	LOG("\n Bootloader Rev: %d", *(uint32_t *)(kbl_param + 0xF8));
	LOG("\n Lboot flags: 0x%08" PRIx32, *(uint32_t *)(kbl_param + 0x6C));
	LOG("\n Hboot flags: 0x%08" PRIx32, *(uint32_t *)(kbl_param + 0xCC));
	LOG("\n Wakeup factor: 0x%08" PRIx32, *(uint32_t *)(kbl_param + 0xC4));
	LOG("\n Hardware Info: 0x%08" PRIx32, *(uint32_t *)(kbl_param + 0xD4));
	LOG("\n Config: 0x%016" PRIx64, *(uint64_t *)(kbl_param + 0xA0));
	LOG("\n DRAM base (p): 0x%08" PRIx32, *(uint32_t *)(kbl_param + 0x60));
	LOG("\n DRAM size: %d bytes", *(uint32_t *)(kbl_param + 0x64));
	LOG("\n SK enp paddr: 0x%08" PRIx32, *(uint32_t *)(kbl_param + 0x80));
	LOG("\n kprx_auth paddr: 0x%08" PRIx32, *(uint32_t *)(kbl_param + 0x90));
	LOG("\n SRVK paddr: 0x%08" PRIx32, *(uint32_t *)(kbl_param + 0x98));
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	LOG_START("vinfo started\n");
	LOG("getting functions... ");
	if (get_fc() < 0)
		return SCE_KERNEL_START_NO_RESIDENT;
	LOG("done\n\n");
	logNfoMain();
	logNfoQa();
	logNfoBattery();
	if (ksceKernelSysrootGetShellPid() < 0) {
		logdev();
	} else {
		siofix(logdev);
	}
	logRawQas();
	
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
