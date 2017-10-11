#include <pthread.h>
#include "chilli.h"

/*
 *	For Test
 *	snmpget -v2c -c yidong 127.0.0.1  1.3.6.1.4.1.5000.1.0
 *	snmpget -v2c -c yidong 127.0.0.1  1.3.6.1.4.1.5000.2.0
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

static const char *conf_agent_name = "CoovaChilli";

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
    	snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (const u_char *)&total, sizeof(int));
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
    	snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (const u_char *)&online, sizeof(int));
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

    oid chilli_total_session_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 1 };
    oid chilli_online_session_oid[] = { 1, 3, 6, 1, 4, 1, 5000, 2 };

    netsnmp_register_scalar(netsnmp_create_handler_registration  
    	("GetTotalPortalSessions", handle_GetTotalPortalSessions, 
	chilli_total_session_oid,  OID_LENGTH(chilli_total_session_oid), HANDLER_CAN_RONLY));  

    netsnmp_register_scalar(netsnmp_create_handler_registration  
      	("GetOnlinePortalSessions", handle_GetOnlinePortalSessions, 
	chilli_online_session_oid,  OID_LENGTH(chilli_online_session_oid), HANDLER_CAN_RONLY));  

#endif

}

static void *snmp_thread(void *a)
{
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
    		agent_check_and_process(1);
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
