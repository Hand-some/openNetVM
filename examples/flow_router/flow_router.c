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

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_flow_table.h"
#include "onvm_flow_dir.h"
#include "onvm_sc_common.h"

#define NF_TAG "flow_router"

/* router information */
uint8_t nf_count;
char * cfg_filename;
struct forward_nf *fwd_nf;

struct forward_nf {
        int32_t hash;
        uint8_t dest;
};
struct flow_table_entry {
        uint32_t count; /* Number of packets in flow */
        uint8_t action; /* Action to be performed */
        uint16_t destination; /* where to go next */
};

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;


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
 * This function parses the forward config. It takes the filename
 * and fills up the forward nf array. This includes the ip and dest
 * address of the onvm_nf
 */

/* Gary's change here. Rewrite the function of parse_router_config.
 * Now the pkt will be routed by its hash key which the form is onvm_ft_ipv4_5tuple. */
static int
parse_router_config(void) {
	int ret, temp, i;
        int32_t hash;
	char * nf_tags;
        FILE * cfg;

        cfg  = fopen(cfg_filename, "r");	// Read the file name. Remember to input the filename in the go.sh
        if (cfg == NULL) {
                rte_exit(EXIT_FAILURE, "Error openning server \'%s\' config\n", cfg_filename);
        }
	// In the config_hash file, first line's second parameter is the default nf router number.
        ret = fscanf(cfg, "%*s %d", &temp);

	if (temp <= 0) {
                rte_exit(EXIT_FAILURE, "Error parsing config, need at least one forward NF configuration\n");
        }
        nf_count = temp;

	
        if (fwd_nf == NULL) {
                rte_exit(EXIT_FAILURE, "Malloc failed, can't allocate forward_nf array\n");
        }

	for (i = 0; i < nf_count; i++) {
                ret = fscanf(cfg, "%I32d %s", &hash, nf_tags);
                if (ret != 2) {
                        rte_exit(EXIT_FAILURE, "Invalid backend config structure\n");
                }


		ret = onvm_pkt_parse_hash_key(hash, &fwd_nf[i].hash);
                if (ret < 0) {
                        rte_exit(EXIT_FAILURE, "Error parsing config hash key #%d\n", i);
                }

                if (nf_tags == NULL) {
                        rte_exit(EXIT_FAILURE, "Error parsing config NF_TAG #%d\n", i);
                }
        }
	return ret;
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

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta, __attribute__((unused)) struct onvm_nf_info *nf_info) {
        static uint32_t counter = 0;
	int i;
        int32_t tbl_index;
        struct onvm_flow_entry *flow_entry;

        if(!onvm_pkt_is_ipv4(pkt)) {
                printf("Non-ipv4 packet\n");
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
                return 0;
        }

        tbl_index = onvm_flow_dir_get_pkt(pkt, &flow_entry);

	if(tbl_index >= 0);

	else if (tbl_index == -ENOENT) {
		#ifdef DEBUG_PRINT
		printf("Unkown flow\n");
		#endif
                /* New flow */
		tbl_index = onvm_flow_dir_add_pkt(pkt, &flow_entry);
        }
        else {
                #ifdef DEBUG_PRINT
                printf("Error in flow lookup: %d (ENOENT=%d, EINVAL=%d)\n", tbl_index, ENOENT, EINVAL);
                onvm_pkt_print(pkt);
                #endif
                onvm_nflib_stop(nf_info);
                rte_exit(EXIT_FAILURE, "Error in flow lookup\n");
        }

	for (i = 0; i < nf_count; i+a+) {
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

        const char *progname = argv[0];
	
        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, &nf_info)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_info);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        parse_router_config();

        // Gary's change for the flow_dir
        onvm_flow_dir_nf_init();
        printf("Starting packet handler.\n");

        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}
