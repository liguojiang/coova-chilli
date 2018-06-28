/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * Copyright (C) 2007-2012 David Bird (Coova Technologies) <support@coova.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "chilli.h"

static char * kname_fmt = "/proc/net/coova/%s";

static unsigned long int totalSessions = 0;
static unsigned long int onlineSessions = 0;

static int
kmod(char cmd, struct in_addr *addr) {
  char file[128];
  char line[256];
  int fd, rd;

  if (!_options.kname) return -1;
  snprintf(file, sizeof(file), kname_fmt, _options.kname);
  fd = open(file, O_RDWR, 0);
  if (fd > 0) {
    if (addr)
      snprintf(line, sizeof(line), "%c%s\n", cmd, inet_ntoa(*addr));
    else
      snprintf(line, sizeof(line), "%c\n", cmd);

    rd = safe_write(fd, line, strlen(line));
    syslog(LOG_DEBUG, "kmod wrote %d %s", rd, line);
    close(fd);
    return rd == strlen(line);
  } else {
    syslog(LOG_ERR, "%s: could not open %s", strerror(errno), file);
  }
  return 0;
}

static int
kmod_allows(char *cmd, char *param) {
  char file[128];
  char line[256];
  int fd, rd;

  if (!_options.kname) return -1;
  snprintf(file, sizeof(file), kname_fmt, "allows");
  fd = open(file, O_RDWR, 0);
  if (fd > 0) {
      snprintf(line, sizeof(line), "%s%s\n", cmd, param);

    rd = safe_write(fd, line, strlen(line));
    syslog(LOG_DEBUG, "kmod cmd wrote %d %s", rd, line);
    close(fd);
    return rd == strlen(line);
  } else {
    syslog(LOG_ERR, "%s: could not open %s", strerror(errno), file);
  }
  return 0;
}

int
kmod_coova_uamserver(char *uamserver) {
  if (_options.debug)
    syslog(LOG_DEBUG, "%s(%d): uamserver [%s]", __FUNCTION__, __LINE__, uamserver);
  return kmod_allows("P", uamserver);
}

int
kmod_coova_nasid(char *nasid) {
  if (_options.debug)
    syslog(LOG_DEBUG, "%s(%d): nasid [%s]", __FUNCTION__, __LINE__, nasid);
  return kmod_allows("N", nasid);
}

int
kmod_coova_nasmac(char *nasmac) {
  if (_options.debug)
    syslog(LOG_DEBUG, "%s(%d): nasmac [%s]", __FUNCTION__, __LINE__, nasmac);
  return kmod_allows("M", nasmac);
}

int
kmod_coova_cna(unsigned int cna) {
  if ( cna ) {
  	if (_options.debug)
    		syslog(LOG_DEBUG, "%s(%d): enable iPhone CNA", __FUNCTION__, __LINE__);
  	return kmod_allows("C", "CNA");
  }else {
  	if (_options.debug)
    		syslog(LOG_DEBUG, "%s(%d): disable iPhone CNA", __FUNCTION__, __LINE__);
  	return kmod_allows("C", "-CNA");
  }
}

int
kmod_coova_ana(unsigned int ana) {
  if ( ana ) {
  	if (_options.debug)
    		syslog(LOG_DEBUG, "%s(%d): enable Android ANA", __FUNCTION__, __LINE__);
  	return kmod_allows("C", "ANA");
  }else {
  	if (_options.debug)
    		syslog(LOG_DEBUG, "%s(%d): disable Android ANA", __FUNCTION__, __LINE__);
  	return kmod_allows("C", "-ANA");
  }
}

int
kmod_coova_update(struct app_conn_t *appconn) {
  return kmod(appconn->s_state.authenticated ? '+' : '-',
     &appconn->hisip);
}

int
kmod_coova_release(struct dhcp_conn_t *conn) {
  return kmod('*', &conn->hisip);
}

int
kmod_coova_clear(void) {
  return kmod('/', 0);
}

unsigned long int kmod_coova_total_sessions(void) {
	return totalSessions;
}

unsigned long int kmod_coova_online_sessions(void) {
	return onlineSessions;
}

int
kmod_coova_sync(void) {
  char file[128];
  char * line = 0;
  size_t len = 0;
  ssize_t read;
  FILE *fp;

  char ip[256];
  unsigned int maci[6];
  unsigned int state;
  unsigned long long int bin;
  unsigned long long int bout;
  unsigned long long int pin;
  unsigned long long int pout;
  struct dhcp_conn_t *conn;

  unsigned long int total = 0;
  unsigned long int online = 0;

  if (!_options.kname) return -1;

  snprintf(file, sizeof(file), kname_fmt, _options.kname);

  fp = fopen(file, "r");
  if (fp == NULL)
    return -1;

  while ((read = getline(&line, &len, fp)) != -1) {
    if (len > 256) {
      syslog(LOG_ERR, "%s: problem", strerror(errno));
      continue;
    }

    if (sscanf(line,
         "mac=%X-%X-%X-%X-%X-%X "
         "src=%s state=%u "
         "bin=%llu bout=%llu "
         "pin=%llu pout=%llu",
         &maci[0], &maci[1], &maci[2], &maci[3], &maci[4], &maci[5],
         ip, &state, &bin, &bout, &pin, &pout) == 12) {
      uint8_t mac[6];
      int i;

      total++;
      if ( 1 == state ) online++;

      for (i=0;i<6;i++)
        mac[i]=maci[i]&0xFF;

      syslog(LOG_ERR, "kmod sync: %s\n", ip);

#ifdef ENABLE_LAYER3
      if (_options.layer3) {
        struct app_conn_t *appconn = NULL;
        if (!inet_aton(ip, &in_ip)) {
            syslog(LOG_ERR, "Invalid IP Address: %s\n", ip);
            return -1;
        }
        appconn = dhcp_get_appconn_ip(0, &in_ip);
        if (appconn) {
            if (_options.swapoctets) {
                appconn->s_state.input_octets = bin;
                appconn->s_state.output_octets = bout;
                appconn->s_state.input_packets = pin;
                appconn->s_state.output_packets = pout;
            } else {
                appconn->s_state.output_octets = bin;
                appconn->s_state.input_octets = bout;
                appconn->s_state.output_packets = pin;
                appconn->s_state.input_packets = pout;
          }
        } else {
            syslog(LOG_DEBUG, "Unknown entry");
        }
      } else {
#endif
        if (!dhcp_hashget(dhcp, &conn, mac)) {
          struct app_conn_t *appconn = conn->peer;
          if (appconn) {
            if (_options.swapoctets) {
              appconn->s_state.input_octets = bin;
              appconn->s_state.output_octets = bout;
              appconn->s_state.input_packets = pin;
              appconn->s_state.output_packets = pout;
            } else {
              appconn->s_state.output_octets = bin;
              appconn->s_state.input_octets = bout;
              appconn->s_state.output_packets = pin;
              appconn->s_state.input_packets = pout;
            }
          } else {
            	syslog(LOG_DEBUG, "Unknown %s.", ip);
          }
        }else {
          syslog(LOG_DEBUG, "Unknown %s, remove it.", ip);
	  total--;
        }
#ifdef ENABLE_LAYER3
      }
#endif
    } else {
      syslog(LOG_ERR, "%s: Error parsing %s", strerror(errno), line);
    }
  }

  if (line)
    free(line);

  fclose(fp);

  totalSessions = total;
  onlineSessions = online;

  return 0;
}
