#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include "tdts_shell_ioctl.h"

static const key_t SHM_KEY_CMD_AGNT = 0x3564;
static const key_t SHM_KEY_RUL_AGNT = 0x3562;
static const key_t SHM_KEY_KA_MEM = 0x3572;
static const key_t SHM_KEY_KA_INFO_MEM = 0x3576;

int g_cmd_agnt_shm_id;
int g_rule_agnt_shm_id;
int *g_cmd_agnt_shm_addr;
int *g_rule_agnt_shm_addr;
size_t g_ano_sec_tbl_len;
size_t g_ka_shm_size;
char *g_rule_path;

// 0x400d10 - 0x400e24
void *CmdAgntInit() {
    void *shmaddr;

    g_cmd_agnt_shm_id = shmget(SHM_KEY_CMD_AGNT, 44, 1974);
    if (g_cmd_agnt_shm_id < 0) {
        printf("%s():%d:shmget() for key=%x, size=%d failed w/ shmid=%d!\n", __func__, __LINE__, SHM_KEY_CMD_AGNT, 44, g_cmd_agnt_shm_id);

        return NULL;
    }

    shmaddr = shmat(g_cmd_agnt_shm_id, NULL, 0);
    if (shmaddr == NULL) {
        printf("%s():%d:shmat() failed!\n", __func__, __LINE__);

        return NULL;
    }

    memset(shmaddr, 0, 44);
    *(uint32_t *)shmaddr = 1;

    return shmaddr;
}

// 0x400e24 - 0x400e84
int detach_cmd_agnt(void *shmaddr) {
    if (shmaddr == NULL) {
        return 0;
    }

    shmdt(shmaddr);

    return shmctl(g_cmd_agnt_shm_id, IPC_RMID, NULL);
}

// 0x400ee0 - 0x401010
void *RulAgntInit() {
    void *shmaddr;

    g_rule_agnt_shm_id = shmget(SHM_KEY_RUL_AGNT, 268, 1974);
    if (g_rule_agnt_shm_id < 0) {
        printf("%s():%d:shmget() for key=%x, size=%d failed w/ shmid=%d!\n", __func__, __LINE__, SHM_KEY_RUL_AGNT, 268, g_rule_agnt_shm_id);

        return NULL;
    }

    shmaddr = shmat(g_rule_agnt_shm_id, NULL, 0);
    if (!shmaddr) {
        printf("%s():%d:shmat() failed!\n", __func__, __LINE__);

        return NULL;
    }

    memset(shmaddr, 0, 268);

    return shmaddr;
}

// 0x4010d0 - 0x40113c
int detach_rule_agnt(void *shmaddr) {
    void *addr;

    if (shmaddr == NULL) {
        return 0;
    }

    memset(shmaddr + 60, 0, 96);
    
    addr = (void *) *(long *)(shmaddr + 52);
    if (addr != NULL) {
        shmdt(addr);
        addr = NULL;
        *(int *)(shmaddr + 260) = 0;
    }

    addr = (void *) *(long *)(shmaddr + 256);
    if (addr != NULL) {
        shmdt(addr);
        addr = NULL;
    }

    shmdt(shmaddr);

    return shmctl(g_rule_agnt_shm_id, IPC_RMID, NULL);
}

// 0x40113c - 0x40128c
int nk_ioctl(int request, tdts_shell_ioctl_t *tdts_shell_ioctl) {
    int result;
    int fd = open("/dev/detector", O_RDWR);

    if (fd > -1) {
        result = ioctl(fd, request, tdts_shell_ioctl);
        if (result != 0) {
            printf("%s():%d:ioctl() failed w/ ret=%d, err(%d)=%s\n", __func__, __LINE__, result, errno, strerror(errno));
            result = -2;
        } else {
            result = 0;
        }

        close(fd);
    } else {
        printf("%s():%d:open %s failed, ret=%d, err(%d)=%s\n", __func__, __LINE__, "/dev/detector", fd, errno, strerror(errno));
        result = -1;
    }

    return result;
}

// 0x40128c - 0x40133c
int trf_load(void *shmaddr, size_t shmsize) {
    tdts_shell_ioctl_t tdts_shell_ioctl;

    tdts_shell_init_ioctl_entry(&tdts_shell_ioctl);

    tdts_shell_ioctl.nr = TDTS_SHELL_IOCTL_NR_SIG;
    tdts_shell_ioctl.op = TDTS_SHELL_IOCTL_SIG_OP_LOAD;

    tdts_shell_ioctl.in_type = TDTS_SHELL_IOCTL_TYPE_RAW;
    tdts_shell_ioctl.in_raw = (uint64_t) shmaddr;
    tdts_shell_ioctl.in_len = shmsize;

    return nk_ioctl(TDTS_SHELL_IOCTL_CMD_SIG, &tdts_shell_ioctl);
}

// 0x40133c - 0x4013ac
int trf_unload() {
    tdts_shell_ioctl_t tdts_shell_ioctl;

    tdts_shell_init_ioctl_entry(&tdts_shell_ioctl);

    tdts_shell_ioctl.nr = TDTS_SHELL_IOCTL_NR_SIG;
    tdts_shell_ioctl.op = TDTS_SHELL_IOCTL_SIG_OP_UNLOAD;

    return nk_ioctl(TDTS_SHELL_IOCTL_CMD_SIG, &tdts_shell_ioctl);
}

// 0x4013ac - 0x40147c
int get_sig_ver(unsigned int *sig_ver, size_t size) {
    size_t out_used_len;
    tdts_shell_ioctl_t tdts_shell_ioctl;
    
    tdts_shell_init_ioctl_entry(&tdts_shell_ioctl);

    tdts_shell_ioctl.nr = TDTS_SHELL_IOCTL_NR_SIG;
    tdts_shell_ioctl.op = TDTS_SHELL_IOCTL_SIG_OP_GET_SIG_VER;

    tdts_shell_ioctl.out = (uint64_t) sig_ver;
    tdts_shell_ioctl.out_used_len = (uint64_t) &out_used_len;
    tdts_shell_ioctl.out_len = size;

    return nk_ioctl(TDTS_SHELL_IOCTL_CMD_SIG, &tdts_shell_ioctl);
}

// 0x401548 - 0x401614
int get_ano_sec_table_len(size_t *tbl_len) {
    size_t out_used_len;
    tdts_shell_ioctl_t tdts_shell_ioctl;
    
    tdts_shell_init_ioctl_entry(&tdts_shell_ioctl);

    tdts_shell_ioctl.nr = TDTS_SHELL_IOCTL_NR_SIG;
    tdts_shell_ioctl.op = TDTS_SHELL_IOCTL_SIG_OP_GET_ANO_SEC_TBL_LEN;

    tdts_shell_ioctl.out = (uint64_t) tbl_len;
    tdts_shell_ioctl.out_used_len = (uint64_t) &out_used_len;
    tdts_shell_ioctl.out_len = 4;

    return nk_ioctl(TDTS_SHELL_IOCTL_CMD_SIG, &tdts_shell_ioctl);
}

// 0x401614 - 0x4016e4
int get_ano_sec_table(void *mem, size_t len) {
    size_t out_used_len;
    tdts_shell_ioctl_t tdts_shell_ioctl;
    
    tdts_shell_init_ioctl_entry(&tdts_shell_ioctl);

    tdts_shell_ioctl.nr = TDTS_SHELL_IOCTL_NR_SIG;
    tdts_shell_ioctl.op = TDTS_SHELL_IOCTL_SIG_OP_GET_ANO_SEC_TBL;

    tdts_shell_ioctl.out = (uint64_t) mem;
    tdts_shell_ioctl.out_used_len = (uint64_t) &out_used_len;
    tdts_shell_ioctl.out_len = len;

    return nk_ioctl(TDTS_SHELL_IOCTL_CMD_SIG, &tdts_shell_ioctl);
}

// 0x4016e4 - 0x401754
int free_shared_info_data() {
    tdts_shell_ioctl_t tdts_shell_ioctl;
    
    tdts_shell_init_ioctl_entry(&tdts_shell_ioctl);

    tdts_shell_ioctl.nr = TDTS_SHELL_IOCTL_NR_SIG;
    tdts_shell_ioctl.op = TDTS_SHELL_IOCTL_SIG_OP_FREE_SHARED_INFO_DATA;

    return nk_ioctl(TDTS_SHELL_IOCTL_CMD_SIG, &tdts_shell_ioctl);
}

// 0x401754 - 0x4017e0
int set_engine_state(int state) {
    tdts_shell_ioctl_t tdts_shell_ioctl;
    
    tdts_shell_init_ioctl_entry(&tdts_shell_ioctl);

    tdts_shell_ioctl.nr = TDTS_SHELL_IOCTL_NR_SIG;
    tdts_shell_ioctl.op = TDTS_SHELL_IOCTL_SIG_OP_SET_STATE;

    tdts_shell_ioctl.in_type = TDTS_SHELL_IOCTL_TYPE_U32;
    tdts_shell_ioctl.in_u32 = state;
    tdts_shell_ioctl.in_len = 4;

    return nk_ioctl(TDTS_SHELL_IOCTL_CMD_SIG, &tdts_shell_ioctl);
}

// 0x4017e0 - 0x4018ac
int get_engine_state(int *state) {
    size_t out_used_len;
    tdts_shell_ioctl_t tdts_shell_ioctl;
    
    tdts_shell_init_ioctl_entry(&tdts_shell_ioctl);

    tdts_shell_ioctl.nr = TDTS_SHELL_IOCTL_NR_SIG;
    tdts_shell_ioctl.op = TDTS_SHELL_IOCTL_SIG_OP_GET_STATE;

    tdts_shell_ioctl.out = (uint64_t) state;
    tdts_shell_ioctl.out_used_len = (uint64_t) &out_used_len;
    tdts_shell_ioctl.out_len = 4;

    return nk_ioctl(TDTS_SHELL_IOCTL_CMD_SIG, &tdts_shell_ioctl);
}

// 0x402780 - 0x402838
int kaStartup() {
    g_cmd_agnt_shm_addr = CmdAgntInit();
    g_rule_agnt_shm_addr = RulAgntInit();

    if (g_cmd_agnt_shm_addr && g_rule_agnt_shm_addr) {
        return 0;
    }

    detach_rule_agnt(g_rule_agnt_shm_addr);
    g_rule_agnt_shm_addr = NULL;
    detach_cmd_agnt(g_cmd_agnt_shm_addr);
    g_cmd_agnt_shm_addr = NULL;

    return -1;
}

// 0x402838 - 0x402928
int get_signature_version(uint16_t *major, uint16_t *minor) {
    int shmid;
    void *shmaddr;

    if (major == NULL || minor == NULL) {
        return -1;
    }

    shmid = shmget(SHM_KEY_RUL_AGNT, 268, 950);
    if (shmid >= 0) {
        shmaddr = shmat(shmid, NULL, 0);

        if (shmaddr != NULL) {
            *major = *(uint16_t *)(shmaddr + 60);
            *minor = *(uint16_t *)(shmaddr + 62);

            shmdt(shmaddr);

            return 0;
        }
    }

    return -1;
}

// 0x4029d4 - 0x402a50
int get_static_ips_vinfo(int unknown, int *major, int *minor, int *patch) {
    if (unknown == 0) {
        *major = 0;
        *minor = 0;
        *patch = 8;
    }

    return 0;
}

// 0x402a50 - 0x402b74
int set_engine_state_checked(int state) {
    int result = 0;
    int shmid;
    int *shmaddr;

    shmid = shmget(SHM_KEY_CMD_AGNT, 44, 950);
    if (shmid < 0) {
        return -1;
    }

    shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == NULL) {
        return -1;
    }

    if (state == 1) {
        *shmaddr = 1;
        *(shmaddr + 4) = 0;
        if (set_engine_state(1) != 0) {
            result = -1;
        }
    } else if (state == 0) {
        *shmaddr = 0;
        *(shmaddr + 4) = 0;
        if (set_engine_state(0) != 0) {
            result = -1;
        }
    } else {
        result = -1;
    }

    shmdt(shmaddr);

    return result;
}

// 0x402b74 - 0x402bdc
int get_engine_state_checked(int *state) {
    if (state == NULL) {
        return -1;
    }

    if (get_engine_state(state) != 0) {
        return -1;
    }

    return 0;
}

// 0x402bdc - 0x402cf0
void signal_handler(int signum) {
    int ka_shm_id, ka_info_shm_id;

    ka_shm_id = shmget(SHM_KEY_KA_MEM, g_ka_shm_size, 950);
    if (ka_shm_id >= 0) {
        shmctl(ka_shm_id, IPC_RMID, NULL);
    }

    ka_info_shm_id = shmget(SHM_KEY_KA_INFO_MEM, g_ano_sec_tbl_len, 950);
    if (ka_info_shm_id >= 0) {
        shmctl(ka_info_shm_id, IPC_RMID, NULL);
    }

    if (g_cmd_agnt_shm_addr != NULL) {
        detach_cmd_agnt(g_cmd_agnt_shm_addr);
        g_cmd_agnt_shm_addr = NULL;
    }

    if (g_rule_agnt_shm_addr != NULL) {
        detach_rule_agnt(g_rule_agnt_shm_addr);
        g_rule_agnt_shm_addr = NULL;
    }
}

// 0x402cf0 - 0x402dd8
int kaGetSharedMemory(void **shmaddr, size_t *shmsize) {
    int shmid = shmget(SHM_KEY_KA_MEM, g_ka_shm_size, 950);
    if (shmid < 0) {
        goto error;
    }

    
    *shmaddr = shmat(shmid, NULL, 0);
    if (*shmaddr != NULL) {
        *shmsize = g_ka_shm_size;

        return 0;
    }

error:
    printf("%s():%d:shmget() or shmat() for key=%x, size=%d failed!\n", __func__, __LINE__, SHM_KEY_KA_MEM, g_ka_shm_size);
    *shmaddr = NULL;
    *shmsize = 0;

    return -1;
}

// 0x402dd8 - 0x402ec4
int kaGetInfoSharedMemory(void **shmaddr, size_t *shmsize) {
    int shmid = shmget(SHM_KEY_KA_INFO_MEM, g_ano_sec_tbl_len, 950);
    if (shmid < 0) {
        goto error;
    }

    *shmaddr = shmat(shmid, NULL, 0);
    if (*shmaddr != NULL) {
        *shmsize = g_ano_sec_tbl_len;

        return 0;
    }

error:
    printf("%s():%d:shmget() or shmat() for key=%x, size=%d failed!\n", __func__, __LINE__, SHM_KEY_KA_INFO_MEM, g_ano_sec_tbl_len);
    *shmaddr = NULL;
    *shmsize = 0;

    return -1;
}

// 0x402ec4 - 0x402f2c
int detach_shm(void *shmaddr) {
    if (shmaddr == NULL) {
        return -1;
    }

    shmdt(shmaddr);
    shmaddr = NULL;

    return 0;
}

// 0x402f94 - 0x403084
int setSigVer(uint16_t major, uint16_t minor, unsigned int patch) {
    int shmid;
    void *shmaddr;

    shmid = shmget(SHM_KEY_RUL_AGNT, 268, 950);
    if (shmid < 0) {
        printf("%s():%d:Get rule agent shared memory fail!\n", __func__, __LINE__);

        return -1;
    }

    shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == NULL) {
        printf("%s():%d:Get rule agent shared memory fail!\n", __func__, __LINE__);

        return -1;
    }

    *(uint16_t *)(shmaddr + 60) = major;
    *(uint16_t *)(shmaddr + 62) = minor;
    *(unsigned int *)(shmaddr + 64) = patch;

    shmdt(shmaddr);

    return 0;
}

// 0x403084 - 0x4032d4
int setInfoSharedMemory(void *memaddr) {
    void *shmaddr;
    size_t shmsize, size, size2;
    FILE *file;

    if (kaGetInfoSharedMemory(&shmaddr, &shmsize) != 0) {
        printf("%s():%d:Failed to get the shared memory for info tables!\n", __func__, __LINE__);

        return -1;
    }

    *(uint16_t *)shmaddr = 1;
    *(uint16_t *)(shmaddr + 2) = 0;
    *(uint16_t *)(shmaddr + 4) = 0;
    *(uint16_t *)(shmaddr + 6) = 0;

    size = *(size_t *)memaddr;
    *(uint32_t *)(shmaddr + 8) = size;
    memcpy(shmaddr + 12, memaddr + 8, size);

    *(uint16_t *)(shmaddr + 12 + size) = 1;
    *(uint16_t *)(shmaddr + 12 + size + 2) = 0;

    size2 = *(size_t *)(memaddr + 4);
    *(uint32_t *)(shmaddr + 12 + size + 4) = size2;
    memcpy(shmaddr + 12 + size + 8, memaddr + 8 + size, size2);

    *(uint16_t *)(shmaddr + 2) = 2;

    if (detach_shm(shmaddr) != 0) {
        printf("%s():%d:Failed to release the shared memory!\n", __func__, __LINE__);
        
        return -1;
    }

    return 0;
}

// 0x4032d4 - 0x403508
int GetPolicy(char *trf_path) {
    int result;
    struct stat buffer;
    void *ka_shm_addr;
    size_t ka_shm_size;

    if (stat(trf_path, &buffer) != 0) {
        printf("%s():%d:Stat %s ERROR\n", __func__, __LINE__, trf_path);

        result = -1;
        goto error;
    }

    g_ka_shm_size = buffer.st_size;

    if (kaGetSharedMemory(&ka_shm_addr, &ka_shm_size) == -1) {
        printf("%s():%d:kaGetSharedMemory() failed!\n", __func__, __LINE__);

        result = -2;
        goto error;
    }

    FILE *file = fopen(trf_path, "rb");
    if (file == NULL) {
        printf("%s():%d:Open %s ERROR\n", __func__, __LINE__, trf_path);

        result = -3;
        goto error;
    }

    result = fread(ka_shm_addr, 1, g_ka_shm_size, file);
    if (result != g_ka_shm_size) {
        printf("%d - %s\n", errno, strerror(errno));
        printf("%s():%d:Read %s(%u) ERROR: %d\n", __func__, __LINE__, trf_path, g_ka_shm_size, result);

        result = -4;
    }
    fclose(file);

error:
    if (ka_shm_addr == NULL) {
        return result;
    }

    if (detach_shm(ka_shm_addr) == -1) {
        printf("%s():%d:Failed to release the shared memory!\n", __func__, __LINE__);
        result = -5;
    }

    return result;
}

// 0x403508 - 0x4037c0
int kaUpdateSig() {
    int result;
    void *shmaddr, *shared_info_addr;
    size_t shmsize, tbl_len;
    unsigned int signature_version[2];

    kaGetSharedMemory(&shmaddr, &shmsize);
    if (shmaddr == NULL || shmsize == 0) {
        printf("%s():%d:Get rule file shared memory fail!\n", __func__, __LINE__);

        return -1;
    }

    trf_unload();
    if (trf_load(shmaddr, g_ka_shm_size) != 0) {
        printf("%s():%d:trf_load error\n", __func__, __LINE__);

        return -1;
    }

    if (get_ano_sec_table_len(&tbl_len) != 0) {
        printf("%s():%d:get shared data len fail\n", __func__, __LINE__);

        return -1;
    }

    tbl_len += 8;

    shared_info_addr = calloc(tbl_len, 1);
    if (shared_info_addr == NULL) {
        printf("%s():%d:Allocate memory for shared info fail!\n", __func__, __LINE__);

        return -1;
    } 

    g_ano_sec_tbl_len = tbl_len;

    result = get_ano_sec_table(shared_info_addr, tbl_len);
    free_shared_info_data();
    if (result != 0) {
        printf("%s():%d:copy shared data fail\n", __func__, __LINE__);
        result = -1;

        goto end;
    }

    if (setInfoSharedMemory(shared_info_addr) == 0) {
        if (get_sig_ver(signature_version, 8) != 0) {
            printf("%s():%d:copy signature version fail\n", __func__, __LINE__);
            result = -1;

            goto end;
        }

        if (setSigVer(signature_version[0] >> 16, signature_version[0] & 0xFFFF, signature_version[1]) != 0) {
            result = -1;
        }
    }

end:
    free(shared_info_addr);

    return result;
}

// 0x4037c0 - 0x40393c
int rm_all_shm() {
    int failed_count = 0, shmid;
    key_t key;
    key_t keys[] = {
        SHM_KEY_CMD_AGNT,
        0x3567,
        SHM_KEY_RUL_AGNT,
        0x3568,
        SHM_KEY_KA_MEM,
        SHM_KEY_KA_INFO_MEM
    };

    for (int i = 0; i < 6; i++) {
        key = keys[i];
        shmid = shmget(key, 0, 438); // SHM_R | SHM_W | ...

        if (shmid >= 0) {
            if (shmctl(shmid, IPC_RMID, NULL) < 0) {
                printf("[%s(%d)]: shmctl() failed to remove SHM w/ key=0x%.4x; err(%d)=%s!\n", __func__, __LINE__, key, errno, strerror(errno));
                failed_count++;
            }
        }
    }

    return failed_count;
}

// 0x40393c - 0x4039a0
void print_usage(char *filename) {
    printf("Usage: %s Options\n", filename);
    puts("Options: ");
    puts("  -r, --rule-path        Specify the rule path (default to ./rule.trf)");
    puts("  -h, --help             Show this help");

    exit(0);
}

// 0x4039a0 - 0x4039ec
void free_rule_path() {
    if (g_rule_path != NULL) {
        free(g_rule_path);
    }
}

// 0x4039ec - 0x403bac
void parse_arguments(int argc, char *argv[]) {
    int option_index = 0, c;
    static struct option long_options[] = {
        { "rule-path", required_argument, 0, 'r' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };


    c = getopt_long(argc, argv, "+r:h", long_options, &option_index);
    if (c == -1) {
        goto end;
    }

    switch (c) {
        case '?':
            printf("Unknown option=%c!\n", optopt);
        case 'h':
            print_usage(basename(argv[0]));
            break;
        case 'r':
            asprintf(&g_rule_path, "%s", optarg);
            break;
        default:
            abort();
    }

end:
    if (g_rule_path == NULL) {
        asprintf(&g_rule_path, "%s", "rule.trf");
    }
}

// 0x403bac - 0x403f40
int main(int argc, char *argv[]) {
    int result, engine_state, ips_major, ips_minor, ips_patch;
    uint16_t sig_major, sig_minor;

    parse_arguments(argc, argv);

    signal(SIGINT, signal_handler);

    if (rm_all_shm() != 0) {
        printf("[%s(%d)]: Failed to clear existent SHM!\n", __func__, __LINE__);

        return -1;
    }

    if (kaStartup() == -1) {
        printf("[%s(%d)]: Failed to startup IPSM userland daemon!\n", __func__, __LINE__);

        return -1;
    }

    printf("[%s(%d)]: kaStartup() passed\n", __func__, __LINE__);

    result = GetPolicy(g_rule_path);
    if (result < 0) {
        printf("[%s(%d)]: GetPolicy() failed!\n", __func__, __LINE__);
        signal_handler(0);

        return -1;
    }

    printf("[%s(%d)]: GetPolicy() passed (ret=%d)\n", __func__, __LINE__, result);

    if (kaUpdateSig() != 0) {
        printf("[%s(%d)]: Failed to load the policy file!\n", __func__, __LINE__);
        signal_handler(0);

        return -1;
    }

    printf("[%s(%d)]: Loading policy succeeded\n", __func__, __LINE__);

    if (get_signature_version(&sig_major, &sig_minor) == 0) {
        printf("[%s(%d)]: Signature version: major = %u, minor = %u\n", __func__, __LINE__, sig_major, sig_minor);
    }

    if (set_engine_state_checked(1) == 0) {
        printf("[%s(%d)]: Enable IPS!\n", __func__, __LINE__);
    }

    if (get_engine_state_checked(&engine_state) == 0) {
        printf("[%s(%d)]: IPS enable = %d\n", __func__, __LINE__, engine_state);
    }

    if (get_static_ips_vinfo(0, &ips_major, &ips_minor, &ips_patch) == 0) {
        printf("[%s(%d)]: IPS-%d.%d.%d\n", __func__, __LINE__, ips_major, ips_minor, ips_patch);
    }

    signal_handler(0);
    printf("[%s(%d)]: kaShutDown()\n", __func__, __LINE__);
    
    return 0;
}
