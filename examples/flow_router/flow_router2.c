/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2017 George Washington University
 *            2015-2017 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * nf_router.c - route packets based on the provided config.
 ********************************************************************/

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_malloc.h>
#include <rte_compat.h>
#include <rte_hash.h>

#include "onvm_nflib.h"
#include "onvm_nflib.c"
#include "onvm_pkt_helper.h"
#include "onvm_flow_table.h"
#include "onvm_flow_dir.h"
#include "onvm_sc_common.h"

#define NF_TAG "flow_router"
#define SET_CORE 8
#define HASH_TABLE_NUM 1024
#define BUF_SIZE 1024

struct forward_nf {
        int32_t hash;
        uint8_t dest;
};

struct file_nf{
        int32_t hash;
        char nf_tag[30];
};

/* router information */
uint8_t nf_count = 0;
char * cfg_filename;
struct forward_nf fwd_nf[20];
char pid_list[20][100];	//Record the pid of each nf
struct file_nf * f_nf;
struct onvm_nf_info * new_nf;   //This variable will be used only when create new_nf in a new thread.
int step_instance_id; 	//This variable will be used when get this nf's instance_id and assign for other nfs.

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;
struct rte_hash* pkt_hash_table;

/* number of package between each print */
static uint32_t print_delay = 1000000;

int getPidByName(char * task_name, char * get_pid);
int start_new_nf_ocore(char * new_nf_tag);

int getPidByName(char * task_name, char * get_pid){
    DIR *dir;
    struct dirent *ptr;
    int i;
    FILE *fp;
    char filepath[50];
    char cur_task_name[50];
    char buf[BUF_SIZE];
    dir = opendir("/proc");
    if (NULL != dir)
    {
        while ((ptr = readdir(dir)) != NULL)
        {
            if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
		continue;
            if (DT_DIR != ptr->d_type)
		continue;

            sprintf(filepath, "/proc/%s/status", ptr->d_name);
            fp = fopen(filepath, "r");
            if (NULL != fp)
            {
                if( fgets(buf, BUF_SIZE-1, fp)== NULL ){
                    fclose(fp);
                    continue;
                }
		sscanf(buf, "%*s %s", cur_task_name);
		if (!strcmp(task_name, cur_task_name))
			for(i = 0; i < nf_count; i++)
				if(strcmp(pid_list[i], ptr->d_name)){  //judge if is the same nf
					strcpy(get_pid, ptr->d_name);
					break;
				}
                fclose(fp);
            }
        }
        closedir(dir);
    }
    return 0;
}

int return_pid_num(char * input_pid){
    int length = strlen(input_pid);
    int i;
    int real_pid = 0;
    for(i = 0; i < length; i++)
        real_pid = real_pid * 10 + (input_pid[i] - '0');
    return real_pid;
}

int start_new_nf_ocore(char * new_nf_tag){
	int corelist = 10;
	int err;
	int dest_sid;
	int service_id = nf_count + 2;
	char dir_group[100];
        char set_core[100];
        char set_task[100];
        char temp_command[100];
        char set_proportion[100];
        char start_nf_command[100];
	char pid_thread[30];
	int pid_nf_thread;
        int proportion = 1024;
	char onvm_path[50];
	
	onvm_path = "";

	if(!strcmp(new_nf_tag, "aes_decrypt")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d %d &", onvm_path, new_nf_tag, corelist, service_id, service_id + 1);
		strcpy(new_nf_tag, "aesdecrypt");
		getPidByName(new_nf_tag, pid_thread);
	}
	else if(!strcmp(new_nf_tag, "aes_encrypt")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d %d &", onvm_path, new_nf_tag, corelist, service_id, service_id + 1);
		strcpy(new_nf_tag, "aesencrypt");
		getPidByName(new_nf_tag, pid_thread);	
	}
	else if(!strcmp(new_nf_tag, "basic_monitor")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d &", onvm_path, new_nf_tag, corelist, service_id);
		strcpy(new_nf_tag, "monitor");
		getPidByName(new_nf_tag, pid_thread);
	}
	else if(!strcmp(new_nf_tag, "bridge")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d &", onvm_path, new_nf_tag, corelist, service_id);
		strcpy(new_nf_tag, "bridge");
		getPidByName(new_nf_tag, pid_thread);	
	}
	else if(!strcmp(new_nf_tag, "flow_tracker")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d %d &", onvm_path, new_nf_tag, corelist, service_id, service_id + 1);
		strcpy(new_nf_tag, "flow_tracker");
		getPidByName(new_nf_tag, pid_thread);
	}
	else if(!strcmp(new_nf_tag, "ndpi_stats")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d &", onvm_path, new_nf_tag, corelist, service_id);
		strcpy(new_nf_tag, "ndpi_stats");
		getPidByName(new_nf_tag, pid_thread);
	}
	//else if(!strcmp(new_nf_tag, "nf_router"))
		//sprintf(start_nf_command, "$ONVM_HOME/examples/%s/go.sh %d %d %s", new_nf_tag, corelist, service_id, route_config);
	else if(!strcmp(new_nf_tag, "scaling_example")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d %d &", onvm_path, new_nf_tag, corelist, service_id, service_id + 1);
		strcpy(new_nf_tag, "scaling");
		getPidByName(new_nf_tag, pid_thread);	
	}
	else if(!strcmp(new_nf_tag, "simple_forward")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d %d &", onvm_path, new_nf_tag, corelist, service_id, service_id + 1);
		strcpy(new_nf_tag, "forward");
		getPidByName(new_nf_tag, pid_thread);	
	}
	else if(!strcmp(new_nf_tag, "speed_tester")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d %d &", onvm_path, new_nf_tag, corelist, service_id, service_id + 1);
		strcpy(new_nf_tag, "speed_tester");
		getPidByName(new_nf_tag, pid_thread);
	}
	else if(!strcmp(new_nf_tag, "test_flow_dir")){
		sprintf(start_nf_command, "nohup %s/examples/%s/go.sh %d %d %d &", onvm_path, new_nf_tag, corelist, service_id, service_id + 1);
		strcpy(new_nf_tag, "test_flow_dir");
		getPidByName(new_nf_tag, pid_thread);
	}
	err = system(start_nf_command);
	strcpy(pid_list[nf_count], pid_thread);
	
	pid_nf_thread = return_pid_num(pid_thread);

	sprintf(dir_group, "sudo mkdir /sys/fs/cgroup/cpu_test/nf%d", service_id);		//create the subcgroup
        err = system(dir_group);
        sprintf(temp_command, "sudo chmod -R 777 /sys/fs/cgroup/cpu_test/nf%d", service_id);	
        err = system(temp_command);
        sprintf(set_core, "sudo echo %d > /sys/fs/cgroup/cpu_test/nf%d/cpuset.cpus", corelist, service_id);	//set the core
        err = system(set_core);
        sprintf(temp_command, "sudo echo 0 > /sys/fs/cgroup/cpu_test/nf%d/cpuset.mems", service_id);		//set the core numa
        err = system(temp_command);
        sprintf(set_task, "sudo echo %d > /sys/fs/cgroup/cpu_test/nf%d/tasks", pid_nf_thread, service_id);		//set the pid
        err = system(set_task);
        sprintf(set_proportion, "sudo echo %d > /sys/fs/cgroup/cpu_test/nf%d/cpu.shares", proportion, service_id);	//set the proportion of the new nf
        err = system(set_proportion);
        if(err == -1){
            return -1;
        }
        return 0;
}

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- <router_config> -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c = 0;

        while ((c = getopt(argc, argv, "f:p:")) != -1) {
                switch (c) {
                case 'f':
                        cfg_filename = strdup(optarg);
                        break;
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'd')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (optopt == 'p')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                        else
                                RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        usage(progname);
                        return -1;
                }
        }

        return optind;
}


/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static uint64_t pkt_process = 0;
        struct ipv4_hdr* ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %"PRIu64"\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}

static struct rte_hash*
get_rte_hash_table(void){
        struct rte_hash* h;
        struct rte_hash_parameters ipv4_hash_params = {
                .name = NULL,
                .entries = HASH_TABLE_NUM,
                .key_len = sizeof(struct onvm_ft_ipv4_5tuple),
                .hash_func = NULL,
                .hash_func_init_val = 0,
        };
        char s[64];
        /* create ipv4 hash table. use core number and cycle counter to get a unique name. */
        ipv4_hash_params.name = s;
        ipv4_hash_params.socket_id = rte_socket_id();
        snprintf(s, sizeof(s), "onvm_ft_%d", rte_lcore_id());
        h = rte_hash_create(&ipv4_hash_params);
        if (h == NULL) {
                return NULL;
        }
        else
                return h;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, __attribute__((unused)) struct onvm_nf_info *nf_info) {
        static uint32_t counter = 0;
        static int flag_hash_table = 1;			//flag_hash_table is for the initialization of hash_table
        int flag_file_read, nf_number, hash;		//flag_file_read is to signal if the file has the hash key
        int i, j, temp, ret, err;
	int dest_flag, new_dest_id = 0; //This flag is to set the fwd_nf->dest when create  new nf from the config file
        int32_t tbl_index;      //This variable is aimed at find the dest
        char new_nf_tag[30], file_nf_tag[30];
        struct onvm_ft_ipv4_5tuple key;
	
        FILE * cfg;
	
        err = onvm_ft_fill_key(&key, pkt);  //get the key from the pkt
        if (err < 0) {
                return err;
        }
	if(flag_hash_table == 1){   //the hash table has not been initialized
                pkt_hash_table = get_rte_hash_table();
                flag_hash_table = 0;		//hash table will not e initialized again.
        }

        tbl_index = rte_hash_lookup_with_hash(pkt_hash_table, (const void *)&key, pkt->hash.rss);
        //find the hash key in the pkt hash table

        if(tbl_index >= 0);//The hash key is already in the hash table, so the flow can auto select the destination without create new nfs.
        else if (tbl_index == -EINVAL){
                #ifdef DEBUG_PRINT
                printf("Error in flow lookup: %d (ENOENT=%d, EINVAL=%d)\n", tbl_index, ENOENT, EINVAL);
                onvm_pkt_print(pkt);
                #endif
                onvm_nflib_stop(nf_info);
                rte_exit(EXIT_FAILURE, "Error in flow lookup\n");
        }
        else {
                #ifdef DEBUG_PRINT
                printf("Unkown flow\n");
                #endif
                /* New flow */
                tbl_index = rte_hash_add_key_with_hash(pkt_hash_table, (const void *)&key, pkt->hash.rss);
		fwd_nf[nf_count].hash = tbl_index;
                /* Read the config file */
                cfg  = fopen(cfg_filename, "r");	// Read the file name. Remember to input the filename in the go.sh
                if (cfg == NULL) {
                        rte_exit(EXIT_FAILURE, "Error openning server \'%s\' config\n", cfg_filename);
                }
                // In the config_hash file, first line's second parameter is the default nf router number.
                ret = fscanf(cfg, "%*s %d", &temp);
                if (ret != 1) {
                        rte_exit(EXIT_FAILURE, "Invalid backend config structure\n");
                }
                if (temp < 0) {
                        rte_exit(EXIT_FAILURE, "Error parsing config, need at least one forward NF configuration\n");
                }
                flag_file_read = 0;	//This variable will will change to 1 unless there is no matching hash
                for (i = 0; i < temp; i++) {
			ret = fscanf(cfg, "%I32d %d", &hash, &nf_number);
			if (ret != 2) {
			    	rte_exit(EXIT_FAILURE, "Invalid backend config structure\n");
			}
			for(j = 0; j < nf_number; j++){
				err = fscanf(cfg, "%s", file_nf_tag);
				if(hash == tbl_index){		//This means that a new nf is needed to be created.
					strcpy(new_nf_tag, file_nf_tag);
					start_new_nf_ocore(new_nf_tag);
					nf_count++;
					flag_file_read = 1;
					if(dest_flag == 1){
						dest_flag = 0;
						fwd_nf[nf_count].dest = nf_count + 1;
						new_dest_id = nf_count + 1;
					}
					else{
						fwd_nf[nf_count].dest = new_dest_id;
					}
				}
				
			}
			if(flag_file_read == 1)
				break;
                }
		fclose(cfg);
                /* config file read finish */

                /* No suitable hash in config file */
                if(flag_file_read == 0){
                        strcpy(new_nf_tag, "basic_monitor");
			start_new_nf_ocore(new_nf_tag);
                        nf_count++;
			fwd_nf[nf_count].dest = nf_count + 1;
                 }
        }
        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
    	}
        for (i = 0; i < nf_count; i++) {
                if (fwd_nf[i].hash == tbl_index) {
                        meta->destination = fwd_nf[i].dest;
                        meta->action = ONVM_NF_ACTION_TONF;
                        return 0;
                }
        }
        meta->action = ONVM_NF_ACTION_DROP;
        meta->destination = 0;
        return 0;
}


int main(int argc, char *argv[]) {
        int arg_offset;
	char finish_command[100];
	int i, err;
        const char *progname = argv[0];
        onvm_path = getenv("ONVM_HOME");


        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, &nf_info)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_info);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        onvm_flow_dir_nf_init();
        printf("Starting packet handler.\n");

        onvm_nflib_run(nf_info, &packet_handler);
	for(i = 0; i < nf_count; i++){
		sprintf(finish_command, "cgdelete cpu,cpuset:nf%d", i + 2);
		err = system(finish_command);
		if(err != -1)
			printf("End of the cgroup!\n");
	}
        printf("If we reach here, program is ending\n");
        return 0;
}
