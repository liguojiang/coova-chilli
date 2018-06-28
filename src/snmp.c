#include <pthread.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include "chilli.h"

/*
 *	For Test
 *	snmpget -v2c -c yidong 127.0.0.1  1.3.6.1.4.1.5000.1.0
 *	snmpget -v2c -c yidong 127.0.0.1  1.3.6.1.4.1.5000.2.0
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

struct netdev_stats {
    unsigned long long rx_packets_m;    /* total packets received       */
    unsigned long long tx_packets_m;        /* total packets transmitted    */
    unsigned long long rx_bytes_m;  /* total bytes received         */
    unsigned long long tx_bytes_m;  /* total bytes transmitted      */
    unsigned long rx_errors_m;      /* bad packets received         */
    unsigned long tx_errors_m;      /* packet transmit problems     */
    unsigned long rx_dropped_m;     /* no space in linux buffers    */
    unsigned long tx_dropped_m;     /* no space available in linux  */
    unsigned long rx_multicast_m;   /* multicast packets received   */
    unsigned long rx_compressed_m;
    unsigned long tx_compressed_m;
    unsigned long collisions_m;

    /* detailed rx_errors: */
    unsigned long rx_length_errors_m;
    unsigned long rx_over_errors_m; /* receiver ring buff overflow  */
    unsigned long rx_crc_errors_m;  /* recved pkt with crc error    */
    unsigned long rx_frame_errors_m;        /* recv'd frame alignment error */
    unsigned long rx_fifo_errors_m; /* recv'r fifo overrun          */
    unsigned long rx_missed_errors_m;       /* receiver missed packet     */
    /* detailed tx_errors */
    unsigned long tx_aborted_errors_m;
    unsigned long tx_carrier_errors_m;
    unsigned long tx_fifo_errors_m;
    unsigned long tx_heartbeat_errors_m;
    unsigned long tx_window_errors_m;
};

static unsigned long long rx = 0;
static unsigned long long tx = 0;
static unsigned long long rx_rate = 0;
static unsigned long long tx_rate = 0;

static const char *conf_agent_name = "CoovaChilli";

#define PROC_NET_DEV_FNAME "/proc/net/dev"
static char *get_name(char *name, char *p)
{
    char *t = NULL;

    /*interface only contains lowercase letters*/
    while((*p<'a') || (*p>'z')) p++;

    if ((t =  strchr(p, ':')))
    {
        memcpy(name, p, t-p);
        return t+1;
    }
    else return NULL;
}

static int get_devstats(char * ifname, struct netdev_stats * pstats)
{
    FILE * fp = NULL;
    char name[256] = {0};
    char buf[256] = {0};
    char * s = NULL;
    int found = 0;


    if (!ifname || !pstats) return -1;

    fp = fopen(PROC_NET_DEV_FNAME, "r");

    if (!fp) return -1;
    else 
    {
        /*by pass the first 2 lines, they are titles*/
        fgets(buf, sizeof(buf), fp );
        fgets(buf, sizeof(buf), fp );

        memset(buf, 0 ,sizeof(buf));
        while (fgets(buf, sizeof(buf), fp )) 
        {
            memset(name, 0, sizeof(name));
            s = get_name(name, buf);

            if (s) {
                if(!strncmp(name, ifname, strlen(ifname)))  {
                    	found = 1;
                	sscanf(s, "%llu%llu%lu%lu%lu%lu%lu%lu%llu%llu%lu%lu%lu%lu%lu%lu",
                       		&pstats->rx_bytes_m, /* missing for 0 */
                       		&pstats->rx_packets_m,
                       		&pstats->rx_errors_m,
                       		&pstats->rx_dropped_m,
                       		&pstats->rx_fifo_errors_m,
                       		&pstats->rx_frame_errors_m,
                       		&pstats->rx_compressed_m, /* missing for <= 1 */
                       		&pstats->rx_multicast_m, /* missing for <= 1 */
                       		&pstats->tx_bytes_m, /* missing for 0 */
                       		&pstats->tx_packets_m,
                       		&pstats->tx_errors_m,
                       		&pstats->tx_dropped_m,
                       		&pstats->tx_fifo_errors_m,
                       		&pstats->collisions_m,
                       		&pstats->tx_carrier_errors_m,
                       		&pstats->tx_compressed_m /* missing for <= 1 */
                    	);
                    	break;
                }
            }
            else continue;
        }
        fclose(fp);
    }

    if (!found) return -1;
    else  return 0;
}

/*
 *	get total portal sessions
 */
int handle_GetTotalPortalSessions(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    unsigned long int total = kmod_coova_total_sessions();
    switch (reqinfo->mode) {
    case MODE_GET:
    	snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, &total, sizeof(int));
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

/*
 *	get online portal sessions
 */
int handle_GetOnlinePortalSessions(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    unsigned long int online = kmod_coova_online_sessions();
    switch (reqinfo->mode) {
    case MODE_GET:
    	snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, &online, sizeof(int));
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

/*
 *	get lan interface
 */
int handle_GetLanInterface(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    switch (reqinfo->mode) {
    case MODE_GET:
    	snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, _options.dhcpif, strlen(_options.dhcpif));
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

/*
 * -1 -- error , details can check errno
 *  1 -- interface link up
 *  0 -- interface link down.
 */
static int get_netlink_status(char *if_name)
{
    int skfd;
    struct ifreq ifr;
    struct ethtool_value edata;

    edata.cmd = ETHTOOL_GLINK;
    edata.data = 0;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_data = (char *) &edata;

    if (( skfd = socket( AF_INET, SOCK_DGRAM, 0 )) == 0)
        return -1;

    if(ioctl( skfd, SIOCETHTOOL, &ifr ) == -1)
    {
        close(skfd);
        return -1;
    }
    close(skfd);
    return edata.data;
}

/*
 *	get lan status
 */
int handle_GetLanStatus(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    int status = get_netlink_status(_options.dhcpif); 
    switch (reqinfo->mode) {
    case MODE_GET:
	if ( 1 == status ) {
    		snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, "up", 2);
	}else if ( 0 == status ) {
    		snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, "down", 4);
	}else {
    		snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, "error", 5);
	}
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

/*
 *	get rx
 */
int handle_GetUpFlow(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    char flow[512];
    sprintf(flow, "%llu", rx);
    switch (reqinfo->mode) {
    case MODE_GET:
    	snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, flow, strlen(flow));
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

/*
 *	get tx
 */
int handle_GetDownFlow(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    char flow[512];
    sprintf(flow, "%llu", tx);
    switch (reqinfo->mode) {
    case MODE_GET:
    	snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, flow, strlen(flow));
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

/*
 *	get rx rate
 */
int handle_GetUpRate(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    char flow[512];
    sprintf(flow, "%llu", rx_rate);
    switch (reqinfo->mode) {
    case MODE_GET:
    	snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, flow, strlen(flow));
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

/*
 *	get tx rate
 */
int handle_GetDownRate(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    char flow[512];
    sprintf(flow, "%llu", tx_rate);
    switch (reqinfo->mode) {
    case MODE_GET:
    	snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, flow, strlen(flow));
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

/*
 *	get hostname
 */
int handle_GetHostname(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    char hostname[256];
    gethostname(hostname, 256);
    switch (reqinfo->mode) {
    case MODE_GET:
    	snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, hostname, strlen(hostname));
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}

void init_chilli_snmp(void)
{

#if 0
    netsnmp_handler_registration *reg;
    netsnmp_watcher_info         *winfo;

    const oid chilli_total_session_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 1 };
    const oid chilli_online_session_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 2 };
    const oid chilli_lan_interface_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 3 };
    const oid chilli_lan_status_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 4 };
    const oid chilli_up_flow_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 5 };
    const oid chilli_down_flow_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 6 };
    const oid chilli_up_rate_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 7 };
    const oid chilli_down_rate_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 8 };
    const oid chilli_hostname_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 9 };

    reg = netsnmp_create_handler_registration(
             "GetTotalPortalSessions", NULL,
              chilli_total_session_oid, OID_LENGTH(chilli_total_session_oid),
              HANDLER_CAN_RONLY);

    winfo = netsnmp_create_watcher_info(
                handle_GetTotalPortalSessions, sizeof(*handle_GetTotalPortalSessions),
                 ASN_INTEGER, WATCHER_FIXED_SIZE);

    if (netsnmp_register_watched_scalar( reg, winfo ) < 0 ) {
        syslog(LOG_DEBUG, "Failed to register watched GetTotalPortalSessions" );
    }

    reg = netsnmp_create_handler_registration(
             "GetOnlinePortalSessions", NULL,
              chilli_online_session_oid, OID_LENGTH(chilli_online_session_oid),
              HANDLER_CAN_RONLY);

    winfo = netsnmp_create_watcher_info(
                handle_GetOnlinePortalSessions, sizeof(*handle_GetOnlinePortalSessions),
                 ASN_INTEGER, WATCHER_FIXED_SIZE);

    if (netsnmp_register_watched_scalar( reg, winfo ) < 0 ) {
        syslog(LOG_DEBUG, "Failed to register watched GetOnlinePortalSessions" );
    }
#else

    const oid chilli_total_session_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 1 };
    const oid chilli_online_session_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 2 };
    const oid chilli_lan_interface_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 3 };
    const oid chilli_lan_status_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 4 };
    const oid chilli_up_flow_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 5 };
    const oid chilli_down_flow_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 6 };
    const oid chilli_up_rate_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 7 };
    const oid chilli_down_rate_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 8 };
    const oid chilli_hostname_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 9 };

    netsnmp_register_scalar(netsnmp_create_handler_registration  
    	("GetTotalPortalSessions", handle_GetTotalPortalSessions, 
	chilli_total_session_oid,  OID_LENGTH(chilli_total_session_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration  
      	("GetOnlinePortalSessions", handle_GetOnlinePortalSessions, 
	chilli_online_session_oid,  OID_LENGTH(chilli_online_session_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration
      	("GetLanInterface", handle_GetLanInterface, 
	chilli_lan_interface_oid, OID_LENGTH(chilli_lan_interface_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration
      	("GetLanStatus", handle_GetLanStatus, 
	chilli_lan_status_oid,  OID_LENGTH(chilli_lan_status_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration
      	("GetUpFlow", handle_GetUpFlow, 
	chilli_up_flow_oid,  OID_LENGTH(chilli_up_flow_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration
      	("GetDownFlow", handle_GetDownFlow, 
	chilli_down_flow_oid,  OID_LENGTH(chilli_down_flow_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration
      	("GetUpRate", handle_GetUpRate, 
	chilli_up_rate_oid,  OID_LENGTH(chilli_up_rate_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration
      	("GetDownRate", handle_GetDownRate, 
	chilli_down_rate_oid,  OID_LENGTH(chilli_down_rate_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration
      	("GetHostname", handle_GetHostname, 
	chilli_hostname_oid,  OID_LENGTH(chilli_hostname_oid), HANDLER_CAN_RONLY));  
#endif

}

static void *snmp_thread(void *a)
{
	struct netdev_stats curr_pstats;
        sigset_t set;

        sigfillset(&set);
        sigdelset(&set, SIGKILL);
        sigdelset(&set, SIGSTOP);
        sigdelset(&set, 32);
        pthread_sigmask(SIG_BLOCK, &set, NULL);

	pthread_detach(pthread_self());

  	snmp_disable_log();
        //snmp_enable_calllog();
        netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
    	/* 120 seconds check alive */
    	netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_AGENTX_PING_INTERVAL, 120);

        init_agent(conf_agent_name);

	init_chilli_snmp();

        init_snmp(conf_agent_name);

        while ( 1 == 1 ) {
        	//syslog(LOG_DEBUG, "snmp agent check and process...");
    		agent_check_and_process(3);

		/* get netflow status */
		get_devstats(_options.dhcpif, &curr_pstats);
		if ( 0 == rx && 0 ==tx ){
			rx = curr_pstats.rx_bytes_m;
			tx = curr_pstats.tx_bytes_m;
		}else {
			rx_rate = (curr_pstats.rx_bytes_m - rx)/3;
			tx_rate = (curr_pstats.tx_bytes_m - tx)/3;
			rx = curr_pstats.rx_bytes_m;
			tx = curr_pstats.tx_bytes_m;
		}
        }

        syslog(LOG_DEBUG, "snmp agent shutdown...");

        snmp_shutdown(conf_agent_name);

        return NULL;
}

void snmp_agent_init(void)
{
	static pthread_t snmp_thr;
        pthread_create(&snmp_thr, NULL, snmp_thread, NULL);
}
