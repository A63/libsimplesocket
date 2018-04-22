/*
    libsimplesocket, abstract socket networking that seamlessly allows both unencrypted and encrypted connections
    Copyright (C) 2017-2018  alicia@ion.nu

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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <gnutls/gnutls.h>
#include "socket.h"

static ssize_t readwrap(void* sock, void* buf, size_t size)
{
  int fd=*(int*)sock;
  if(fd==SIMPLESOCK_STDIO){fd=0;}
  return read(fd, buf, size);
}

static ssize_t writewrap(void* sock, const void* buf, size_t size)
{
  int fd=*(int*)sock;
  if(fd==SIMPLESOCK_STDIO){fd=1;}
  return write(fd, buf, size);
}

SimpleSocket* simplesocket_new(int sock, char server)
{
  SimpleSocket* ss=malloc(sizeof(SimpleSocket));
  ss->sock=sock;
  ss->server=server;
  ss->tls=0;
  return ss;
}

SimpleSocket* simplesocket_connect(const char* host, const char* proto)
{
  int sock;
  struct addrinfo* ai=0;
  getaddrinfo(host, proto, 0, &ai);
  struct addrinfo* i;
  for(i=ai; i; i=i->ai_next)
  {
    sock=socket(i->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if(!connect(sock, i->ai_addr, i->ai_addrlen)){break;}
    close(sock);
  }
  freeaddrinfo(ai);
  if(!i){return 0;}
  return simplesocket_new(sock, 0);
}

ssize_t simplesocket_read(SimpleSocket* ss, void* buf, size_t len)
{
  if(ss->tls)
  {
    return gnutls_record_recv(ss->tls, buf, len);
  }else{
    return readwrap(ss, buf, len);
  }
}

ssize_t simplesocket_write(SimpleSocket* ss, const void* buf, size_t len)
{
  if(ss->tls)
  {
    return gnutls_record_send(ss->tls, buf, len);
  }else{
    return writewrap(ss, buf, len);
  }
}

int simplesocket_close(SimpleSocket* ss)
{
  if(ss->tls)
  {
    gnutls_deinit(ss->tls);
  }
  int r=close(ss->sock);
  free(ss);
  return r;
}

static void loadfile(gnutls_datum_t* data, const char* file)
{
  struct stat st;
  if(stat(file, &st)){perror(file); return;}
  data->size=st.st_size;
  data->data=malloc(data->size);
  int f=open(file, O_RDONLY);
  read(f, data->data, data->size);
  close(f);
}

int simplesocket_starttls(SimpleSocket* ss, const char* cert, const char* key)
{
  gnutls_global_init();
  gnutls_certificate_credentials_t cred;
  gnutls_certificate_allocate_credentials(&cred);
  if(cert && key)
  {
    gnutls_datum_t certdata={.data=(unsigned char*)cert, .size=strlen(cert)};
    gnutls_datum_t keydata={.data=(unsigned char*)key, .size=strlen(key)};
    if(strncmp(cert, "-----BEGIN ", 11)){loadfile(&certdata, cert);}
    if(strncmp(key, "-----BEGIN ", 11)){loadfile(&keydata, key);}
    if(gnutls_certificate_set_x509_key_mem(cred, &certdata, &keydata, GNUTLS_X509_FMT_PEM))
    {
      printf("Failed to load cert/key files '%s' and '%s'\n", cert, key);
      return -1;
    }
    if(certdata.data!=(void*)cert){free(certdata.data);}
    if(keydata.data!=(void*)key){free(keydata.data);}
  }
  gnutls_priority_t prio;
  gnutls_priority_init(&prio, "NORMAL:%COMPAT", 0);

  gnutls_init(&ss->tls, (cert&&key)?GNUTLS_SERVER:GNUTLS_CLIENT);
  gnutls_priority_set(ss->tls, prio);
  gnutls_credentials_set(ss->tls, GNUTLS_CRD_CERTIFICATE, cred);
  gnutls_certificate_server_set_request(ss->tls, ss->server?GNUTLS_CERT_IGNORE:GNUTLS_CERT_REQUIRE);
  gnutls_transport_set_ptr(ss->tls, &ss->sock);
  gnutls_transport_set_pull_function(ss->tls, readwrap);
  gnutls_transport_set_push_function(ss->tls, writewrap);
  int ret;
  do{
    ret=gnutls_handshake(ss->tls);
  }
  while(ret<0 && !gnutls_error_is_fatal(ret));
  if(ret<0)
  {
    printf("TLS handshake failed: %i\n", ret);
    gnutls_deinit(ss->tls);
    ss->tls=0;
  }
  return ret;
}
