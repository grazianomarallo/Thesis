/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include <ell/ell.h>

static struct l_io *io;
static struct l_tls *tls;
bool served;

static void https_io_disconnect(struct l_io *io, void *user_data)
{
	if (!served)
		printf("Disconnected before serving a page\n");
	l_main_quit();
}

static bool https_io_read(struct l_io *io, void *user_data)
{
	uint8_t buf[2048];
	int l;

	l = read(l_io_get_fd(io), buf, sizeof(buf));
	if (l == 0) {
		if (!served)
			printf("EOF before serving a page\n");
		l_main_quit();
	} else if (l > 0)
		l_tls_handle_rx(tls, buf, l);

	return true;
}

static void https_tls_disconnected(enum l_tls_alert_desc reason, bool remote,
					void *user_data)
{
	if (reason)
		printf("TLS error: %s\n", l_tls_alert_to_str(reason));
	l_main_quit();
}

static void https_new_data(const uint8_t *data, size_t len, void *user_data)
{
	char *reply = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n"
		"\r\n"
		"Hello, world!\n";

	if (len >= 4 && !memcmp(data + len - 4, "\r\n\r\n", 4)) {
		l_tls_write(tls, (void *) reply, strlen(reply));
		served = true;
		printf("Hello world page served\n");
		l_tls_close(tls);
	}
}

static void https_tls_write(const uint8_t *data, size_t len, void *user_data)
{
	int r;

	while (len) {
		r = send(l_io_get_fd(io), data, len, MSG_NOSIGNAL);
		if (r < 0) {
			printf("send error\n");
			l_main_quit();
			break;
		}
		len -= r;
		data += r;
	}
}

static void https_tls_ready(const char *peer_identity, void *user_data)
{
	if (peer_identity)
		printf("Client authenticated as %s\n", peer_identity);
	else
		printf("Client not authenticated\n");
}

static void https_tls_debug_cb(const char *str, void *user_data)
{
	printf("%s\n", str);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in addr;
	int fd, listenfd;
	bool auth_ok;

	if (argc != 4 && argc != 5) {
		printf("Usage: %s <server-cert-path> <server-key-path> "
				"<server-key-passphrase> [<ca-cert-path>]\n"
				"Note: The passphrase will be ignored if the "
				"key is not encrypted.\n",
				argv[0]);

		return -1;
	}

	l_log_set_stderr();

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &(int) { 1 },
			sizeof(int));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(1234);

	if (bind(listenfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		printf("bind: %s\n", strerror(errno));
		return -1;
	}
	if (listen(listenfd, 1) == -1) {
		printf("listen: %s\n", strerror(errno));
		return -1;
	}

	printf("Try https://localhost:1234/ now\n");

	fd = accept(listenfd, NULL, NULL);
	close(listenfd);
	if (fd == -1) {
		printf("accept: %s\n", strerror(errno));
		return -1;
	}

	if (!l_main_init())
		return -1;

	io = l_io_new(fd);
	l_io_set_close_on_destroy(io, true);
	l_io_set_read_handler(io, https_io_read, tls, NULL);
	l_io_set_disconnect_handler(io, https_io_disconnect, tls, NULL);

	tls = l_tls_new(true, https_new_data, https_tls_write,
			https_tls_ready, https_tls_disconnected, NULL);

	if (getenv("TLS_DEBUG"))
		l_tls_set_debug(tls, https_tls_debug_cb, NULL, NULL);

	auth_ok = l_tls_set_auth_data(tls, argv[1], argv[2], argv[3]) &&
		(argc <= 4 || l_tls_set_cacert(tls, argv[4]));

	if (tls && auth_ok)
		l_main_run();
	else
		printf("TLS setup failed\n");

	l_io_destroy(io);
	l_tls_free(tls);

	l_main_exit();

	return 0;
}
