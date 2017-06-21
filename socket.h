/*
    libsimplesocket, abstract socket networking that seamlessly allows both unencrypted and encrypted connections
    Copyright (C) 2017  alicia@ion.nu

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <gnutls/gnutls.h>
#define SIMPLESOCK_STDIO -1
typedef struct
{
  int sock;
  char server;
  gnutls_session_t tls;
} SimpleSocket;

extern SimpleSocket* simplesocket_new(int sock, char server);
extern SimpleSocket* simplesocket_connect(const char* host, const char* proto);
extern ssize_t simplesocket_read(SimpleSocket* ss, void* buf, size_t len);
extern ssize_t simplesocket_write(SimpleSocket* ss, const void* buf, size_t len);
extern int simplesocket_close(SimpleSocket* ss);
extern int simplesocket_starttls(SimpleSocket* ss, const char* cert, const char* key);
