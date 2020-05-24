/*
 *    Copyright (C) 2020 Igor Mokrushin aka McMCC <mcmcc@mail.ru>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License along
 *    with this program; if not, write to the Free Software Foundation, Inc.,
 *    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <mtd/mtd-user.h>
#include <sys/ioctl.h>
#include "mongoose.h"

#ifdef MY_DEBUG
#define TYP_FILE	"./is_dvbt.lock"
#define FW_FILE		"./firmware.bin"
#define CFG_FILE	"./config.conf"
#define VER_FILE	"./version"
#define PAS_FILE	"./htpasswd"
#define ROOT_DIR	"./web"
#define HTTP_PORT	"8000"
#else
#define TYP_FILE	"/var/is_dvbt.lock"
#define FW_FILE		"/var/firmware.bin"
#define CFG_FILE	"/home/gx/etc/config.conf"
#define VER_FILE	"/etc/version"
#define PAS_FILE	"/var/htpasswd"
#define ROOT_DIR	"/usr/share/webif"
#define HTTP_PORT	"80"
#endif
#define MTD_UPDATE	"/dev/mtd5"
#define AUTH_DOMAIN	"gx6605s"
#define BUFSIZE		(4 * 1024)
#define SHM_SIZE	512
#define BUF_SIZE	256
#define V_SIZE		32
#define P_SIZE		20

struct file_writer_data
{
	FILE *fp;
	size_t bytes_written;
};

struct device_settings {
	const char *name;
	char setting[BUF_SIZE];
};

typedef struct proc_data {
	int lock;
	int update_complite;
	unsigned int start_addr;
	unsigned int total_size;
	char msg[BUF_SIZE];
} proc_data_t;

typedef struct _MemOccupy
{
	char name[P_SIZE];
	char name2[P_SIZE];
	unsigned long total;
	unsigned long free;
	unsigned long cache;
	unsigned long buffer;
} MemOccupy;

typedef struct _CpuOccupy
{
	char name[P_SIZE];
	unsigned int user;
	unsigned int nice;
	unsigned int system;
	unsigned int idle;
} CpuOccupy;

extern int check_valid_fw(FILE *fp);
extern unsigned int start_addr;
extern unsigned int total_size;
static MemOccupy mem_stat;
static unsigned int cpu_ratio;
static CpuOccupy cpu_stat1;
static CpuOccupy cpu_stat2;
static int file_valid = -1;
#ifdef USE_MMAP
static void *addr_shm = NULL;
#endif
static proc_data_t *fwp = NULL;
static const char *s_http_port = HTTP_PORT;
static struct mg_serve_http_opts s_http_server_opts;
static int count_reboot = 0;

/* default config */
static struct device_settings d_settings[] = {
	{ "SATIP_OPT", "" },
	{ "SATIP_RESTART", "0" },
	{ "FE_PROFILE", "" },
	{ "HW_ADDR", "" },
	{ "LOCAL_IP", "192.168.30.111" },
	{ "NET_MASK", "255.255.255.0" },
	{ "ROUTE_IP", "192.168.30.1" },
	{ "DNS1", "8.8.8.8" },
	{ "DNS2", "8.8.4.4" },
	{ "DNS3", "" },
	{ "TIMEZONE", "MSK-3" },
	{ "NTP_SERVER", "0.pool.ntp.org" },
	{ "PASS_ADMIN", "" },
	{ "EN_ANT_PWR", "" },
	{ "EN_ETH_PROMISC", "" },
	{ NULL, {0,} }
};

/* copy default config */
static struct device_settings s_settings[] = {
	{ "SATIP_OPT", "" },
	{ "SATIP_RESTART", "0" },
	{ "FE_PROFILE", "" },
	{ "HW_ADDR", "" },
	{ "LOCAL_IP", "192.168.30.111" },
	{ "NET_MASK", "255.255.255.0" },
	{ "ROUTE_IP", "192.168.30.1" },
	{ "DNS1", "8.8.8.8" },
	{ "DNS2", "8.8.4.4" },
	{ "DNS3", "" },
	{ "TIMEZONE", "MSK-3" },
	{ "NTP_SERVER", "0.pool.ntp.org" },
	{ "PASS_ADMIN", "" },
	{ "EN_ANT_PWR", "" },
	{ "EN_ETH_PROMISC", "" },
	{ NULL, {0,} }
};

static void xfgets(char *str, int size, FILE *in)
{
	if (fgets(str, size, in) == NULL)
		fprintf(stderr, "%s: Error in reading or end of file.\n", __func__);
}

static int check_flock(char *fname)
{
	FILE *fd;

	fd = fopen (fname, "r");
	if(!fd)
		return 0;

	fclose(fd);
	return 1;
}

static void mem_occupy_get(MemOccupy *mem)
{
	FILE *fd;
	char buff[BUF_SIZE] = { 0, };
	MemOccupy *m;
	m = mem;

	fd = fopen ("/proc/meminfo", "r");

	xfgets (buff, sizeof(buff), fd);
	sscanf (buff, "%s %lu %s", m->name, &m->total, m->name2);

	xfgets (buff, sizeof(buff), fd);
	sscanf (buff, "%s %lu %s", m->name2, &m->free, m->name2);

	xfgets (buff, sizeof(buff), fd);
	sscanf (buff, "%s %lu %s", m->name2, &m->cache, m->name2);

	xfgets (buff, sizeof(buff), fd);
	sscanf (buff, "%s %lu %s", m->name2, &m->buffer, m->name2);

	fclose(fd);
}

static unsigned int cpu_occupy_cal(CpuOccupy *old, CpuOccupy *new)
{
	unsigned long od, nd;
	unsigned long total, idle;
	unsigned int cpu_use = 0;

	od = (unsigned long)(old->user + old->nice + old->system +old->idle);
	nd = (unsigned long)(new->user + new->nice + new->system +new->idle);

	total = (unsigned long)(nd - od);
	idle  = (unsigned long)(new->idle - old->idle);
	if((nd - od) != 0)
	{
		cpu_use = (total - idle) * 100 / total;
	}
	else
		cpu_use = 0;

	return cpu_use;
}

static void cpu_occupy_get(CpuOccupy *cpust)
{
	FILE *fd;
	char buff[BUF_SIZE] = { 0, };
	CpuOccupy *cpu_occupy;


	fd = fopen ("/proc/stat", "r");
	xfgets (buff, sizeof(buff), fd);

	cpu_occupy = cpust;
	sscanf (buff, "%s %u %u %u %u", cpu_occupy->name, &cpu_occupy->user, &cpu_occupy->nice,&cpu_occupy->system, &cpu_occupy->idle);

	fclose(fd);
}

static void sysinfo(void)
{
	cpu_occupy_get((CpuOccupy *)&cpu_stat1);
	sleep(1);
	cpu_occupy_get((CpuOccupy *)&cpu_stat2);
	cpu_ratio = cpu_occupy_cal((CpuOccupy *)&cpu_stat1, (CpuOccupy *)&cpu_stat2);

	mem_occupy_get((MemOccupy *)&mem_stat);

	cpu_occupy_get((CpuOccupy *)&cpu_stat1);
}

static void handle_upload(struct mg_connection *nc, int ev, void *p)
{
	struct file_writer_data *data = (struct file_writer_data *) nc->user_data;
	struct mg_http_multipart_part *mp = (struct mg_http_multipart_part *) p;

	switch (ev) {
		case MG_EV_HTTP_PART_BEGIN: {
			if (data == NULL) {
				data = calloc(1, sizeof(struct file_writer_data));
				data->fp = fopen(FW_FILE, "w+");
				data->bytes_written = 0;

				if (data->fp == NULL) {
					mg_printf(nc, "%s",
						"HTTP/1.1 500 Failed to open a file\r\n"
						"Content-Length: 0\r\n\r\n");
					nc->flags |= MG_F_SEND_AND_CLOSE;
					free(data);
					return;
				}
				nc->user_data = (void *)data;
			}
			break;
		}
		case MG_EV_HTTP_PART_DATA: {
			if (fwrite(mp->data.p, 1, mp->data.len, data->fp) != mp->data.len) {
				mg_printf(nc, "%s",
					"HTTP/1.1 500 Failed to write to a file\r\n"
					"Content-Length: 0\r\n\r\n");
				nc->flags |= MG_F_SEND_AND_CLOSE;
				return;
			}
			data->bytes_written += mp->data.len;
			break;
		}
		case MG_EV_HTTP_PART_END: {
			size_t l = 0;
			mg_printf(nc,
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: text/plain\r\n"
				"Connection: close\r\n\r\n");
			l = (long)ftell(data->fp);
			fwp->update_complite = 0;
			if(!(file_valid = check_valid_fw(data->fp))) {
				mg_printf(nc, "File firmware uploaded, size of %ld bytes\n\n",(long int)l);
#ifdef MY_DEBUG
				printf("Write in flash start addr: 0x%08X, len = %u\n", start_addr, total_size);
#endif
				fwp->start_addr = start_addr;
				fwp->total_size = total_size;
			} else {
				mg_printf(nc, "File firmware wrong!!!\n\n");
				fwp->start_addr = 0;
				fwp->total_size = 0;
			}
			nc->flags |= MG_F_SEND_AND_CLOSE;
			fflush(data->fp);
			fclose(data->fp);
			free(data);
			nc->user_data = NULL;
			if(file_valid < 0)
				unlink(FW_FILE);
			break;
		}
	}
}

static int config_file(int cmd)
{
	FILE *fp;
	char opt[V_SIZE] = { 0, }, str[BUF_SIZE] = { 0, };
	char buf[LINE_MAX] = { 0, };
	int i;

	if(cmd) {
		fp = fopen(CFG_FILE, "w");
		if(!fp)
			return -1;

		i = 0;
		while(s_settings[i].name) {
			fprintf(fp, "%s=\"%s\"\n", s_settings[i].name, s_settings[i].setting);
			i++;
		}
		fflush(fp);
	} else {
		fp = fopen(CFG_FILE, "r");
		if(!fp)
			return -1;

		memset(opt, 0, sizeof(opt));
		memset(str, 0, sizeof(str));
		memset(buf, 0, sizeof(buf));

		while (fgets(buf, sizeof(buf), fp) != NULL) {

			if(sscanf(buf, "%[^=]=\"%[^\"]\"", opt, str) < 2)
				continue;

			if(opt[0] == '#')
				continue;
			/* printf("%s, %s\n", opt, str); */
			i = 0;
			while(s_settings[i].name) {
				if(!strncmp(opt, s_settings[i].name, sizeof(opt))) {
					strncpy(s_settings[i].setting, str, sizeof(str));
					break;
				}
				i++;
			}
			memset(opt, 0, sizeof(opt));
			memset(str, 0, sizeof(str));
			memset(buf, 0, sizeof(buf));
		}
	}

	fclose(fp);
	return 0;
}

static void handle_save(struct mg_connection *nc, struct http_message *hm)
{
	int i = 0;

#ifdef MY_DEBUG
	printf("Save....\n");
#endif

	/* Get form variables and store settings values */
	while(s_settings[i].name) {
		mg_get_http_var(&hm->body, s_settings[i].name, s_settings[i].setting, sizeof(s_settings[i].setting));
		i++;
	}

#ifdef MY_DEBUG
	i = 0;
	printf("Settings updated:\n");
	while(s_settings[i].name) {
		printf("%s=\"%s\"\n", s_settings[i].name, s_settings[i].setting);
		i++;
	}
#endif
	config_file(1);

	/* Send response */
	mg_printf(nc, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%.*s",
		(unsigned long)hm->body.len, (int)hm->body.len, hm->body.p);
}

static void handle_reset(struct mg_connection *nc, struct http_message *hm)
{
	int i = 0;

#ifdef MY_DEBUG
	printf("Reset....\n");
#endif

	unlink(CFG_FILE);

	/* Get form variables and store settings values */
	while(s_settings[i].name) {
		strncpy(s_settings[i].setting, d_settings[i].setting, sizeof(s_settings[i].setting));
		i++;
	}

	config_file(1);

	mg_printf(nc, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%.*s",
		(unsigned long)hm->body.len, (int)hm->body.len, hm->body.p);
}

static void handle_resatip(struct mg_connection *nc, struct http_message *hm)
{
#ifdef MY_DEBUG
	printf("Restart minisatip....\n");
#else
	system("/etc/rcS.d/S98minisatip restart");
#endif
	mg_printf(nc, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%.*s",
		(unsigned long)hm->body.len, (int)hm->body.len, hm->body.p);
}

#ifndef MY_DEBUG
void* system_reboot(void *arg)
{
	sleep(2);
	system("sync && reboot");
	return 0;
	arg = arg;
}
#endif

static void handle_reboot(struct mg_connection *nc, struct http_message *hm)
{
#ifdef MY_DEBUG
	printf("Reboot...\n");
#else
	if(!count_reboot) {
		pthread_t thread;
		int status;

		status = pthread_create(&thread, NULL, system_reboot, NULL);
		if (status != 0) {
			printf("main error: can't create thread, status = %d\n", status);
			goto cont;
		}
	}
	count_reboot++;
cont:
#endif
	mg_printf(nc, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%.*s",
		(unsigned long)hm->body.len, (int)hm->body.len, hm->body.p);
}

static void up_progress(proc_data_t *p, int mode, unsigned long count, unsigned long total)
{
	unsigned long percent;

	percent = count * 100;
	if (total)
		percent = percent / total;

	memset(p->msg, 0, BUF_SIZE);
	snprintf(p->msg, BUF_SIZE, "%s: %05lu/%05lu (%lu%%)",
		(mode < 0) ? "Erasing block" : ((mode == 0) ? "Writing kB" : "Verifying kB"),
		count, total, percent);
}

void* fw_update(void *arg)
{
	int i;
	proc_data_t *p = (proc_data_t *)arg;
	unsigned long erase_count = 0;
	struct mtd_info_user info;
	struct erase_info_user e;
#ifndef MY_DEBUG
	static unsigned char buff1[BUFSIZE] = { 0, };
	static unsigned char buff2[BUFSIZE] = { 0, };
	int fd_d = -1, fd_f = -1;
#endif
	sync();
	sleep(1);
	memset(p->msg, 0, BUF_SIZE);
#ifndef MY_DEBUG
	fd_f = open(FW_FILE, O_RDONLY);
	if(fd_f < 0) {
		snprintf(p->msg, BUF_SIZE, "Problem: Not open firmware file!");
		goto err;
	}

	fd_d = open(MTD_UPDATE, O_RDWR);
	if(fd_d < 0) {
		close(fd_f);
		snprintf(p->msg, BUF_SIZE, "Problem: Not open %s!", MTD_UPDATE);
		goto err;
	}

	if(ioctl(fd_d, MEMGETINFO, &info) < 0) {
		close(fd_f);
		close(fd_d);
		snprintf(p->msg, BUF_SIZE, "Problem: Not get info from %s!", MTD_UPDATE);
		goto err;
	}

	if(p->total_size > info.size) {
		close(fd_f);
		close(fd_d);
		snprintf(p->msg, BUF_SIZE, "Problem: File firmware is big!");
		goto err;
	}

	system("/etc/rcS.d/S98minisatip stop");
#else
	info.erasesize = 64 * 1024;
	info.size = p->total_size;
#endif
	erase_count = (p->total_size + info.erasesize - 1) / info.erasesize;
	e.length = info.erasesize;

	/* Erase partition */
	e.start = 0;
	for (i = 1; i <= (int)erase_count; i++) {
		up_progress(p, -1, i, erase_count);
#ifndef MY_DEBUG
		ioctl(fd_d, MEMUNLOCK, &e);
		if (ioctl(fd_d, MEMERASE, &e) < 0) {
			close(fd_f);
			close(fd_d);
			snprintf(p->msg, BUF_SIZE, "Problem: Erase error at 0x%08X on %s!",
				e.start, MTD_UPDATE);
			goto err;
		}
#else
		usleep(100*100);
#endif
		e.start += info.erasesize;
	}

	/* Write and Verify partition */
	for (i = 0; i <= 1; i++) {
		unsigned long done = 0;
		unsigned long count = BUFSIZE;
#ifndef MY_DEBUG
		lseek(fd_f, p->start_addr, SEEK_SET);
		lseek(fd_d, 0, SEEK_SET);
#endif
		while(1) {
			unsigned long rem;

			up_progress(p, i, done / 1024, p->total_size / 1024);
			rem = p->total_size - done;
			if(!rem)
				break;
			if (rem < BUFSIZE)
				count = rem;
#ifndef MY_DEBUG
			read(fd_f, buff1, count);
			if(!i) {
				int ret;
				if (count < BUFSIZE)
					memset((char*)buff1 + count, 0, BUFSIZE - count);
				ret = write(fd_d, buff1, BUFSIZE);
				if (ret != BUFSIZE) {
					close(fd_f);
					close(fd_d);
					snprintf(p->msg, BUF_SIZE, "Problem: Write error at 0x%08lx on %s, write returned %d!",
						done, MTD_UPDATE, ret);
					goto err;
				}
			} else {
				read(fd_d, buff2, count);
				if (memcmp(buff1, buff2, count) != 0) {
					close(fd_f);
					close(fd_d);
					snprintf(p->msg, BUF_SIZE, "Problem: Verification mismatch at 0x%08lx!", done);
					goto err;
				}
			}
#else
			usleep(100*100);
#endif
			done += count;
		}
	}

	sleep(2);
	snprintf(p->msg, BUF_SIZE, "Reboot");
#ifndef MY_DEBUG
	close(fd_f);
	close(fd_d);
err:
#endif
	sleep(2);
	p->update_complite = 1;
	pthread_exit(NULL);
	return 0;
}

static int run_update(proc_data_t *p)
{
	pthread_t thread;
	int status;

	status = pthread_create(&thread, NULL, fw_update, p);
	if (status != 0) {
		printf("main error: can't create thread, status = %d\n", status);
		return -1;
	}
	p->lock = 1;
	return 0;
}


static void handle_update(struct mg_connection *nc)
{
#ifdef MY_DEBUG
	printf("Update....\n");
#endif

	if(!fwp->lock && !file_valid)
		run_update(fwp);

	if(fwp->update_complite && !file_valid) {
		if((1 < count_reboot) && (count_reboot < 3)) {
#ifdef MY_DEBUG
			printf("Sync && Reboot...\n");
#else
			system("sync && reboot");
#endif
		}
		count_reboot++;
	}

	// Use chunked encoding in order to avoid calculating Content-Length
	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");

	if((file_valid < 0) || fwp->update_complite)
		mg_printf_http_chunk(nc, "{ \"upresult\": \"\" }");
	else {
		mg_printf_http_chunk(nc, "{ \"upresult\": \"%s\" }", fwp->msg);
	}
	// Send empty chunk, the end of response
	mg_send_http_chunk(nc, "", 0);
}

static void handle_ssi_call(struct mg_connection *nc, const char *param)
{
	int i = 0;
	int is_dvbt = check_flock(TYP_FILE);

	config_file(0);

	if (strcmp("is_dvbt", param) == 0) {
		mg_printf(nc, "%s", is_dvbt ? "block" : "none");
	}

	while(s_settings[i].name) {
		if (strcmp("EN_ANT_PWR", param) == 0) {
			if (strcmp(s_settings[i].setting, "on") == 0) mg_printf(nc, "checked");
		} else if (strcmp("EN_ETH_PROMISC", param) == 0) {
			if (strcmp(s_settings[i].setting, "yes") == 0) mg_printf(nc, "checked");
		} else if (strcmp(param, s_settings[i].name) == 0)
			mg_printf_html_escape(nc, "%s", s_settings[i].setting);
		i++;
	}
}

static char *get_fw_version(void)
{
	FILE *fd;
	static char verbuff[BUF_SIZE] = { 0, };
	char *p = "";

	fd = fopen (VER_FILE, "r");
	if(!fd)
		return p;

	memset(verbuff, 0, sizeof(verbuff));
	xfgets(verbuff, sizeof(verbuff), fd);
	fclose(fd);

	p = strtok(verbuff, "\n");
	if(!p)
		p = "";

	return p;
}

static void handle_get_info(struct mg_connection *nc)
{
	char buff[BUF_SIZE / 2];
	time_t now = time (0);
	char *p = "";

	sysinfo();

	strftime(buff, sizeof(buff), "%a %b %d %H:%M:%S %z %Y", localtime(&now));

	p = get_fw_version();

	// Use chunked encoding in order to avoid calculating Content-Length
	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");

	// Output JSON object which holds CPU usage data and etc...
	mg_printf_http_chunk(nc, "{ \"cpu_usage\": %d, \"mem_free\": %d, \"mem_total\": %d, \"version\": \"%s\", \"ctime\": \"%s\" }",
		cpu_ratio, mem_stat.free, mem_stat.total, p, buff);

	// Send empty chunk, the end of response
	mg_send_http_chunk(nc, "", 0);
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
	struct http_message *hm = (struct http_message *) ev_data;

	switch (ev) {
		case MG_EV_HTTP_REQUEST:
			if (mg_vcmp(&hm->uri, "/save") == 0) {
				handle_save(nc, hm);
			} else if (mg_vcmp(&hm->uri, "/restart_satip") == 0) {
				handle_resatip(nc, hm);
			} else if (mg_vcmp(&hm->uri, "/reset") == 0) {
				handle_reset(nc, hm);
			} else if (mg_vcmp(&hm->uri, "/reboot") == 0) {
				handle_reboot(nc, hm);
			} else if (mg_vcmp(&hm->uri, "/update") == 0) {
				handle_update(nc);
			} else if (mg_vcmp(&hm->uri, "/info") == 0) {
				handle_get_info(nc);
			} else {
				mg_serve_http(nc, hm, s_http_server_opts);
			}
			break;
		case MG_EV_SSI_CALL:
			handle_ssi_call(nc, ev_data);
			break;
		default:
			break;
	}
}

int main(void)
{
	struct mg_mgr mgr;
	struct mg_connection *nc;

#ifdef USE_MMAP
	addr_shm = mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(!addr_shm) {
		printf("Problem mmap()...\n");
		return -1;
	}
	fwp = (proc_data_t *)addr_shm;
#else
	proc_data_t fwt;
	memset(&fwt, 0, sizeof(proc_data_t));
	fwp = &fwt;
#endif
	fwp->update_complite = 0;
	fwp->lock = 0;
	fwp->start_addr = 0;
	fwp->total_size = 0;

	mg_mgr_init(&mgr, NULL);
	nc = mg_bind(&mgr, s_http_port, ev_handler);
	mg_register_http_endpoint(nc, "/upload", handle_upload MG_UD_ARG(NULL));
	mg_set_protocol_http_websocket(nc);
	s_http_server_opts.document_root = ROOT_DIR;

	s_http_server_opts.auth_domain = AUTH_DOMAIN;
	s_http_server_opts.global_auth_file = PAS_FILE;

#ifdef MY_DEBUG
	printf("Starting device configurator on port %s\n", s_http_port);
#endif

	for (;;) {
		mg_mgr_poll(&mgr, 1000);
	}
	mg_mgr_free(&mgr);
#ifdef USE_MMAP
	munmap(addr_shm, SHM_SIZE);
#endif

	return 0;
}
