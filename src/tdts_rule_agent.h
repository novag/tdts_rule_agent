#ifndef TDTS_RULE_AGENT_H
#define TDTS_RULE_AGENT_H

void *CmdAgntInit();
void *RulAgntInit();
int detach_cmd_agnt(void *shmaddr);
int detach_rule_agnt(void *shmaddr);
int detach_shm(void *shmaddr);
void free_rule_path();
int free_shared_info_data();
int get_ano_sec_table_len(size_t *tbl_len);
int get_ano_sec_table(void *mem, size_t len);
int get_engine_state_checked(int *state);
int get_engine_state(int *state);
int get_sig_ver(unsigned int *sig_ver, size_t size);
int get_signature_version(uint16_t *major, uint16_t *minor);
int get_static_ips_vinfo(int unknown, int *major, int *minor, int *patch);
int GetPolicy(char *trf_path);
int kaGetInfoSharedMemory(void **shmaddr, size_t *shmsize);
int kaGetSharedMemory(void **shmaddr, size_t *shmsize);
int kaStartup();
int kaUpdateSig();
int nk_ioctl(int request, tdts_shell_ioctl_t *tdts_shell_ioctl);
void parse_arguments(int argc, char *argv[]);
void print_usage(char *filename);
int rm_all_shm();
int set_engine_state_checked(int state);
int set_engine_state(int state);
int setInfoSharedMemory(void *memaddr);
int setSigVer(uint16_t major, uint16_t minor, unsigned int patch);
void signal_handler(int signum);
int trf_load(void *shmaddr, size_t shmsize);
int trf_unload();

#endif
