#include "xdpi.h"

int nDPI_LogLevel = 0;
char *_debug_protocols = NULL;
u_int8_t enable_protocol_guess = 1;
u_int32_t current_ndpi_memory, max_ndpi_memory;
// flow preferences
ndpi_workflow_prefs_t flow_prefs = {
        .decode_tunnels=0,
        .quiet_mode=1,
        .num_roots=NUM_ROOTS,
        .max_ndpi_flows = MAX_NDPI_FLOWS
};

struct reader_thread {
    struct ndpi_workflow *workflow;
    pthread_t pthread;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
};

struct flow_info {
    struct ndpi_flow_info *flow;
};

struct ndpi_workflow *workflow;

static void on_protocol_discovered(struct ndpi_workflow *workflow, struct ndpi_flow_info *flow, void *udata);

static struct reader_thread reader;
static u_int8_t undetected_flows_deleted = 0;

static int all_num_flows = 0;
static struct flow_info *all_flows;

static struct timeval pcap_start = {0, 0}, pcap_end = {0, 0}, program_start = {0, 0};

static pcap_t *handler = NULL;

struct ndpi_packet_trailer {
    u_int32_t magic; /* 0x19682017 */
    u_int16_t master_protocol /* e.g. HTTP */, app_protocol /* e.g. FaceBook */;
    char name[16];
};

static void node_print_unknown_proto_walker(const void *node,
                                            ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    if (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) return;
    if ((which == ndpi_preorder) || (which == ndpi_leaf)) {
        /* Avoid walking the same node multiple times */
        all_flows[all_num_flows].flow = flow;
        all_num_flows++;
    }
}

static void node_print_known_proto_walker(const void *node,
                                          ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) return;
    if ((which == ndpi_preorder) || (which == ndpi_leaf)) {
        /* Avoid walking the same node multiple times */
        all_flows[all_num_flows].flow = flow;
        all_num_flows++;
    }
}


static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if ((!flow->detection_completed) && flow->ndpi_flow)
            flow->detected_protocol = ndpi_detection_giveup(reader.workflow->ndpi_struct, flow->ndpi_flow,
                                                            enable_protocol_guess);

        process_ndpi_collected_info(reader.workflow, flow);

        reader.workflow->stats.protocol_counter[flow->detected_protocol.app_protocol] +=
                flow->src2dst_packets + flow->dst2src_packets;
        reader.workflow->stats.protocol_counter_bytes[flow->detected_protocol.app_protocol] +=
                flow->src2dst_bytes + flow->dst2src_bytes;
        reader.workflow->stats.protocol_flows[flow->detected_protocol.app_protocol]++;
    }
}

static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;

    if (reader.num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
        return;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if (flow->last_seen + MAX_IDLE_TIME < reader.workflow->last_time) {

            /* update stats */
            node_proto_guess_walker(node, which, depth, user_data);

            if ((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
                undetected_flows_deleted = 1;

            ndpi_free_flow_info_half(flow);
            reader.workflow->stats.ndpi_flow_count--;

            /* adding to a queue (we can't delete it from the tree inline ) */
            reader.idle_flows[reader.num_idle_flows++] = flow;
        }
    }
}


void initDetect(pcap_t *handle) {
    handler = handle;
    reader.workflow = ndpi_workflow_init(&flow_prefs, handler);

    ndpi_set_detection_preferences(reader.workflow->ndpi_struct,
                                   ndpi_pref_http_dont_dissect_response, 0);
    ndpi_set_detection_preferences(reader.workflow->ndpi_struct,
                                   ndpi_pref_dns_dont_dissect_response, 0);
    ndpi_set_detection_preferences(reader.workflow->ndpi_struct,
                                   ndpi_pref_enable_category_substring_match, 1);

    ndpi_workflow_set_flow_detected_callback(reader.workflow, on_protocol_discovered,
                                             NULL);

    // enable all protocols
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(reader.workflow->ndpi_struct, &all);

    // clear memory for results
    memset(reader.workflow->stats.protocol_counter, 0,
           sizeof(reader.workflow->stats.protocol_counter));
    memset(reader.workflow->stats.protocol_counter_bytes, 0,
           sizeof(reader.workflow->stats.protocol_counter_bytes));
    memset(reader.workflow->stats.protocol_flows, 0,
           sizeof(reader.workflow->stats.protocol_flows));
}

static void printFlow(struct ndpi_flow_info *flow, struct result *res) {
    struct result *tmp;
    tmp = (struct result*)malloc(sizeof(struct result));
    tmp->flow = (struct ndpi_flow_info*)malloc(sizeof(struct ndpi_flow_info));
    tmp->flow->protocol = flow->protocol;
    tmp->flow->src_port = flow->src_port;
    tmp->flow->dst_port = flow->dst_port;
    strcpy(tmp->flow->src_name,flow->src_name);
    strcpy(tmp->flow->dst_name,flow->dst_name);
    if(flow->detected_protocol.master_protocol){
        char buf[64];
        strcpy(tmp->flow->protocol_name,ndpi_protocol2name(reader.workflow->ndpi_struct, flow->detected_protocol, buf, sizeof(buf)));
    }else{
        strcpy(tmp->flow->protocol_name,ndpi_get_proto_name(reader.workflow->ndpi_struct, flow->detected_protocol.app_protocol));
    }
    tmp->next = res->next;
    res->next = tmp;

//    struct ndpi_flow_info *flow = reader.idle_flows[--reader.num_idle_flows];
//    struct result *tmp;
//    tmp = (struct result*)malloc(sizeof(struct result));
//    tmp->flow->protocol = flow->protocol;
//    tmp->flow->src_port = flow->src_port;
//    tmp->flow->dst_port = flow->dst_port;
//    strcpy(tmp->flow->src_name,flow->src_name);
//    strcpy(tmp->flow->dst_name,flow->dst_name);
//    tmp->next = result->next;
//    fprintf(stdout,"%s:%u,%s,%u\n",tmp->flow->src_name,htons(tmp->flow->src_port),tmp->flow->dst_name,htons(tmp->flow->dst_port));
//    result->next = tmp;
//    char out[1000];
//    struct result tmp;
//    int j = 0;
//    j = snprintf(out, sizeof(out), "%"PRIu64",%d,", flow->last_seen, 0);

//    if (flow->vlan_id > 0) {
//        j += snprintf(out + j, sizeof(out), "%u,", flow->vlan_id);
//    } else {
//        j += snprintf(out + j, sizeof(out), "-1,");
//    }
//    if (flow->detected_protocol.master_protocol) {
//        char buf[64];
//        j += snprintf(out + j, sizeof(out), "%u,%u,%s,", flow->detected_protocol.master_protocol,
//                      flow->detected_protocol.app_protocol,
//                      ndpi_protocol2name(reader.workflow->ndpi_struct, flow->detected_protocol, buf, sizeof(buf)));
//    } else
//        j += snprintf(out + j, sizeof(out), "-1,%u,%s,", flow->detected_protocol.app_protocol,
//                      ndpi_get_proto_name(reader.workflow->ndpi_struct, flow->detected_protocol.app_protocol));

//    j += snprintf(out + j, sizeof(out), "%s,%u,%s,%u,%u,%u,%llu,%llu,%u,%llu,", flow->src_name, htons(flow->src_port),
//                  flow->dst_name,
//                  htons(flow->dst_port),
//                  flow->src2dst_packets, flow->dst2src_packets, flow->src2dst_bytes, flow->dst2src_bytes,
//                  flow->src2dst_packets + flow->dst2src_packets, flow->src2dst_bytes + flow->dst2src_bytes);

//    if (flow->host_server_name[0] != '\0') {
//        j += snprintf(out + j, sizeof(out), "%s,", flow->host_server_name);
//    } else {
//        j += snprintf(out + j, sizeof(out), ",");
//    }
//    if (flow->info[0] != '\0') {
//        j += snprintf(out + j, sizeof(out), "%s,", flow->info);
//    } else {
//        j += snprintf(out + j, sizeof(out), ",");
//    }

//    if (flow->ssh_ssl.client_info[0] != '\0') {
//        j += snprintf(out + j, sizeof(out), "%s,", flow->ssh_ssl.client_info);
//    } else {
//        j += snprintf(out + j, sizeof(out), ",");
//    }
//    if (flow->ssh_ssl.server_info[0] != '\0') {
//        j += snprintf(out + j, sizeof(out), "%s,", flow->ssh_ssl.server_info);
//    } else {
//        j += snprintf(out + j, sizeof(out), ",");
//    }
//    if (flow->bittorent_hash[0] != '\0') {
//        j += snprintf(out + j, sizeof(out), "%s", flow->bittorent_hash);
//    }
//    if (j > sizeof(out) - 1) {
//        fprintf(stdout, "strcat error, no enough buffer\n");
//    } else {
//        fprintf(stdout, "%s\n", out);
//    }
}

void handlePacket(const struct pcap_pkthdr *header, const u_char *packet,struct result * result){
    struct ndpi_proto p;
    uint8_t *packet_checked = malloc(header->caplen);
    memcpy(packet_checked, packet, header->caplen);
    p = ndpi_workflow_process_packet(reader.workflow, header, packet_checked);

    if (reader.last_idle_scan_time + IDLE_SCAN_PERIOD < reader.workflow->last_time) {
        /* scan for idle flows */
        ndpi_twalk(reader.workflow->ndpi_flows_root[reader.idle_scan_idx],
                   node_idle_scan_walker, NULL);

        /* remove idle flows (unfortunately we cannot do this inline) */
        while (reader.num_idle_flows > 0) {
            /* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
            printFlow(reader.idle_flows[--reader.num_idle_flows] ,result);
            ndpi_tdelete(reader.idle_flows[reader.num_idle_flows],
                         &reader.workflow->ndpi_flows_root[reader.idle_scan_idx],
                         ndpi_workflow_node_cmp);

            /* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
            ndpi_free_flow_info_half(reader.idle_flows[reader.num_idle_flows]);
            ndpi_free(reader.idle_flows[reader.num_idle_flows]);
        }

        if (++reader.idle_scan_idx == reader.workflow->prefs.num_roots) reader.idle_scan_idx = 0;
        reader.last_idle_scan_time = reader.workflow->last_time;
    }
    free(packet_checked);
}

static void on_protocol_discovered(struct ndpi_workflow *workflow, struct ndpi_flow_info *flow, void *udata) {
}
