/*
 * $Id$
 *
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
 *
 * Written by Björn Stenberg <bjorn@haxx.se> for .SE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <unistd.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <ldns/ldns.h>

#include "config.h"

static const char* head =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
    "<epp xmlns=\"urn:ietf:params:xml:ns:epp-1.0\"\n"
    " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
    " xsi:schemaLocation=\"urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd\">\n";

static const char* foot = "</epp>\n";

static CURL* curl = NULL;
static char curlerr[CURL_ERROR_SIZE];

static xmlXPathContext* xml_parse(char* string)
{
    xmlDoc* doc = xmlParseMemory(string, strlen(string));
    if (!doc) {
        syslog(LOG_DEBUG, "error: could not parse string: %s", string);
        return NULL;
    }

    xmlXPathContext* context = xmlXPathNewContext(doc);
    if(!context) {
        syslog(LOG_DEBUG,"error: unable to create new XPath context");
        xmlFreeDoc(doc); 
        return NULL;
    }

    xmlXPathRegisterNs(context, (xmlChar*)"epp", (xmlChar*)"urn:ietf:params:xml:ns:epp-1.0");
    xmlXPathRegisterNs(context, (xmlChar*)"domain", (xmlChar*)"urn:ietf:params:xml:ns:domain-1.0");
    xmlXPathRegisterNs(context, (xmlChar*)"secdns", (xmlChar*)"urn:ietf:params:xml:ns:secDNS-1.0");
    
    return context;
}

static char* xml_get(xmlXPathContext* xml, char* path)
{
    char* result = NULL;

    xmlXPathObject* obj = xmlXPathEvalExpression((xmlChar*)path, xml);
    if (obj) {
        if (obj->nodesetval->nodeNr) {
            xmlNode* node = obj->nodesetval->nodeTab[0];
            if (node && node->children && node->children->content)
                result = strdup((char*)(node->children->content));
        }
        xmlXPathFreeObject(obj);
    }
    else
        syslog(LOG_DEBUG,
               "Error: unable to evaluate xpath expression '%s'", path);
    
    return result;
}

static void xml_free(xmlXPathContext* xml)
{
    xmlDoc* doc = xml->doc;
    xmlXPathFreeContext(xml);
    xmlFreeDoc(doc);
}

/* curl_easy_recv() is non-blocking, so we may have to loop */
static int curl_read(CURL* curl, char* dest, int len)
{
    int count = 0;
    while (count < len) {
        size_t got;
        int rc = curl_easy_recv(curl, dest, len - count, &got);
        if (rc && rc != CURLE_AGAIN) {
            syslog(LOG_ERR, "recv error: %d (%s)", rc, curlerr);
            return -1;
        }
            
        count += got;

        if (count < len) {
            /* wait 100ms */
            struct timespec delay = {0, 100000000};
            nanosleep(&delay, NULL);
        }
    }

    return 0;
}

/* curl_easy_send() is non-blocking, so we may have to loop */
static int curl_write(CURL* curl, char* dest, int len)
{
    int count = 0;
    while (count < len) {
        size_t got;
        int rc = curl_easy_send(curl, dest, len - count, &got);
        if (rc && rc != CURLE_AGAIN) {
            syslog(LOG_ERR, "send error: %d (%s)", rc, curlerr);
            return -1;
        }
            
        count += got;

        if (count < len) {
            /* wait 100ms */
            struct timespec delay = {0, 100000000};
            nanosleep(&delay, NULL);
        }
    }

    return 0;
}

static xmlXPathContext* read_frame(void)
{
    static char buffer[8192];

    if (curl_read(curl, buffer, 4))
        return NULL;

    int len = ntohl(*((uint32_t*)buffer));
    len -= 4;

    if (len >= (int)sizeof(buffer)) {
        len = sizeof(buffer) - 1; /* leave room for \0 */
        syslog(LOG_DEBUG,
               "Read frame is larger than buffer. Shrinking to %d bytes", len);
    }

    if (curl_read(curl, buffer, len))
        return NULL;

    buffer[sizeof(buffer)-1] = 0;
    buffer[len] = 0;

#ifdef DEBUG
    FILE* f = fopen("input.xml", "w");
    if (f) {
        fwrite(buffer, len, 1, f);
        fclose(f);
    }
#endif

    return xml_parse(buffer);
}

static int send_frame(char* ptr, int len)
{
    char buf[4];

    *((uint32_t*)buf) = htonl(len+4);

    int rc = curl_write(curl, buf, 4);
    if (rc)
        return -1;

    rc = curl_write(curl, ptr, len);
    if (rc)
        return -1;

#ifdef DEBUG
    FILE* f = fopen("output.xml", "w");
    if (f) {
        fprintf(f, "%02x %02x %02x %02x (%d)\n",
                buf[0], buf[1], buf[2], buf[3], len);
        fwrite(ptr, len, 1, f);
        fclose(f);
    }
#endif

    return 0;
}


static int read_response(xmlXPathContext** return_xml)
{
    int rc = -1;
    xmlXPathContext* xml = read_frame();

    char* code = xml_get(xml, "//epp:result/@code");
    char* msg = xml_get(xml, "//epp:result/epp:msg");

    if (code && msg) {
        syslog(LOG_DEBUG, "<< result %s (%s)", code, msg);
                
        rc = atoi(code);

        free(msg);
        free(code);
    }
    else
        syslog(LOG_ERR, "No <msg> in <result>");
    
    if (rc != 1000) {
        char* reason = xml_get(xml, "//epp:reason");
        if (reason) {
            syslog(LOG_DEBUG, "Failure reson: %s", reason);
            free(reason);
        }
        else
            syslog(LOG_DEBUG, "No failure reason in response");
    }
    else
        rc = 0;

    if (return_xml)
        *return_xml = xml;
    else
        xml_free(xml);

    return rc;
}

static xmlXPathContext* read_greeting(void)
{
    xmlXPathContext* response = read_frame();
    char* version = xml_get(response, "//epp:svcMenu/epp:version");
    if (version) {
        syslog(LOG_DEBUG, "<< greeting %s", version);
        free(version);

        char* dnssec = xml_get(response, "//epp:svcExtension[epp:extURI = \"urn:ietf:params:xml:ns:secDNS-1.0\"]");
        if (!dnssec) {
            syslog(LOG_ERR, "Server doesn't support DNSSEC extension");
            xml_free(response);
            return NULL;
        }
        else
            free(dnssec);
    }
    else {
        syslog(LOG_ERR, "No <version> in xml");
        xml_free(response);
        return NULL;
    }

    return response;
}

void epp_cleanup(void)
{
    if (curl) {
        curl_easy_cleanup(curl);
    }
}

static int login(xmlXPathContext* greeting, char* registry)
{
    char* version = xml_get(greeting, "//epp:svcMenu/epp:version");
    if (!version) {
        syslog(LOG_ERR, "No <version> in greeting!");
        return -1;
    }

    char* lang = xml_get(greeting, "//epp:svcMenu/epp:lang");
    if (!lang) {
        syslog(LOG_ERR, "No <lang> in greeting!");
        free(version);
        return -1;
    }

    char* user = strdup(config_registry_value(registry, "clID"));
    char* pass = strdup(config_registry_value(registry, "pw"));
    char* ext = strdup(config_registry_value(registry, "svcExtension"));
    
    /* construct login xml */
    char buffer[4096];
    snprintf(buffer, sizeof buffer,
             "%s"
             "<command>\n"
             " <login>\n"
             "  <clID>%s</clID>\n"
             "  <pw>%s</pw>\n"
             "  <options>\n"
             "   <version>%s</version>\n"
             "   <lang>%s</lang>\n"
             "  </options>\n"
             "  <svcs>\n"
             "   <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>\n"
             "   <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>\n"
             "   <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>\n"
             "   <svcExtension>\n"
             "    <extURI>urn:ietf:params:xml:ns:secDNS-1.0</extURI>\n"
             "    %s"
             "   </svcExtension>\n"
             "  </svcs>\n"
             " </login>\n"
             "</command>\n"
             "%s",
             head,
             user,
             pass,
             version, lang,
             ext,
             foot);

    free(user);
    free(pass);
    free(ext);
    free(version);
    free(lang);

    syslog(LOG_DEBUG,">> login");
    send_frame(buffer, strlen(buffer));

    if (read_response(NULL))
        return -1;

    return 0;
}

int epp_logout(void)
{
    /* construct logout xml */
    char buffer[4096];
    snprintf(buffer, sizeof buffer,
             "%s"
             "<command>\n"
             " <logout/>\n"
             "</command>\n"
             "%s",
             head,
             foot);

    syslog(LOG_DEBUG,">> logout");
    send_frame(buffer, strlen(buffer));

    /* ignore result - server disconnects after <logout> */

    return 0;
}

int epp_login(char* registry)
{
    char* host = strdup(config_registry_value(registry, "host"));
    char* port = strdup(config_registry_value(registry, "port"));
    char url[80];
    snprintf(url, sizeof url, "https://%s:%s", host, port);
    free(host);
    free(port);

    curl = curl_easy_init();
    if (!curl) {
        syslog(LOG_ERR, "Failed initializing curl");
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlerr);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

    char* c = config_registry_value(registry, "clientcert/file");
    if (c && c[0]) {
        curl_easy_setopt(curl,CURLOPT_SSLCERT, c);

        c = config_registry_value(registry, "clientcert/type");
        if (!c[0]) {
            syslog(LOG_ERR, "No client <clientcert><type> for registry %s",
                   registry);
            return -1;
        }
        curl_easy_setopt(curl,CURLOPT_SSLCERTTYPE, c);

        c = config_registry_value(registry, "clientkey/file");
        if (!c[0]) {
            syslog(LOG_ERR, "No <clientkey><file> for registry %s", registry);
            return -1;
        }
        curl_easy_setopt(curl,CURLOPT_SSLKEY, c);

        c = config_registry_value(registry, "clientkey/type");
        if (!c[0]) {
            syslog(LOG_ERR, "No <clientkey><type> for registry %s", registry);
            return -1;
        }
        curl_easy_setopt(curl,CURLOPT_SSLKEYTYPE, c);
        
        c = config_registry_value(registry, "clientkey/password");
        if (!c[0]) {
            syslog(LOG_ERR, "No <clientkey><password> for registry %s",
                   registry);
            return -1;
        }
        curl_easy_setopt(curl,CURLOPT_KEYPASSWD, c);
    }

    int rc = curl_easy_perform(curl);
    if (rc) {
        syslog(LOG_ERR, "connect error: %s", curlerr);
        return -1;
    }

    xmlXPathContext* greeting = read_greeting();
    if (greeting) {
        rc = login(greeting, registry);
        xml_free(greeting);
    }

    return rc;
}

static void bin2hex(char* src, char* dest, int bytes)
{
    static const char int2hex[16] = "0123456789ABCDEF";

    while (bytes--) {
        *dest++ = int2hex[*src >> 4];
        *dest++ = int2hex[*src & 15];
        src++;
    }
    *dest = 0;
}

static int format_dsdata(char* zone, char* key, char* dest)
{
    char line[1024];

    /* build a DNSKEY RR for digest and keytag calculation */
    snprintf(line, sizeof line, "%s. 3600 IN DNSKEY %s", zone, key);
    ldns_rr* rr;
    int error = ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
    if (error) {
        syslog(LOG_ERR, "ldns_rr_new_frm_str(%s) returned NULL", line);
        return -1;
    }

    uint16_t keytag = ldns_calc_keytag(rr);

    /* build a <secDNS:digest> (RFC4034 5.1.4) */
    ldns_buffer* wiredata = ldns_buffer_new(1024);
    error = ldns_rr_rdata2buffer_wire(wiredata, rr);
    if (error) {
        syslog(LOG_ERR, "ldns_rr_rdata2buffer_wire() returned %d (%s)",
               error, ldns_get_errorstr_by_id(error));
        return -1;
    }
    ldns_rdf* owner = ldns_rr_owner(rr);
    int len = ldns_rdf_size(owner);
    memcpy(dest, ldns_rdf_data(owner), ldns_rdf_size(owner));
    memcpy(dest + len, wiredata->_data, wiredata->_position);
    len += wiredata->_position;

    char digest[20];
    ldns_sha1((unsigned char*)dest, len, (unsigned char*)digest);
    char digest_hex[41];
    bin2hex(digest, digest_hex, 20);

    ldns_rdf* algorithm = ldns_rr_dnskey_algorithm(rr);
    if (!algorithm) {
        syslog(LOG_ERR, "ldns_rr_dnskey_algorithm() returned NULL");
        return -1;
    }
    ldns_buffer_free(wiredata);

    len = sprintf(dest,
                  "    <secDNS:dsData>\n"
                  "      <secDNS:keyTag>%d</secDNS:keyTag>\n"
                  "      <secDNS:alg>%d</secDNS:alg>\n"
                  "      <secDNS:digestType>1</secDNS:digestType>\n"
                  "      <secDNS:digest>%s</secDNS:digest>\n"
                  "    </secDNS:dsData>\n",
                  keytag,
                  ldns_rdf2native_int8(algorithm),
                  digest_hex);

    ldns_rr_free(rr);
    
    return len;
}

int epp_change_key(char* zone, char** keys, int keycount)
{
    int outsize = 4096;
    int outlen = 0;
    char* outbuf = malloc(outsize);

    outlen +=
        sprintf(outbuf,
                "%s"
                "<command>\n"
                " <update>\n"
                "  <domain:update\n"
                "   xmlns:domain=\"urn:ietf:params:xml:ns:domain-1.0\"\n"
                "   xsi:schemaLocation=\"urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd\">\n"
                "    <domain:name>%s</domain:name>\n"
                "  </domain:update>\n"
                " </update>\n"
                " <extension>\n"
                "  <secDNS:update\n"
                "   xmlns:secDNS=\"urn:ietf:params:xml:ns:secDNS-1.0\"\n"
                "   xsi:schemaLocation=\"urn:ietf:params:xml:ns:secDNS-1.0 secDNS-1.0.xsd\">\n"
                "   <secDNS:chg>\n",
                head,
                zone);

    for (int i=0; i<keycount; i++) {
        char dsdata[4096];
        int dslen = format_dsdata(zone, keys[i], dsdata);
        if (dslen < 1) {
            free(outbuf);
            return -1;
        }

        /* make space for dsdata */
        if (outlen + dslen > outsize) {
            outsize *= 2;
            outbuf = realloc(outbuf, outsize);
        }
        strcpy(outbuf + outlen, dsdata);
        outlen += dslen;
    }

    /* make space for footer */
    if (outlen + 100 > outsize) {
        outsize *= 2;
        outbuf = realloc(outbuf, outsize);
    }

    outlen += sprintf(outbuf + outlen,
                      "   </secDNS:chg>\n"
                      "  </secDNS:update>\n"
                      " </extension>\n"
                      "</command>\n"
                      "%s",
                      foot);
    
    syslog(LOG_DEBUG,">> change key");
    send_frame(outbuf, outlen);
    free(outbuf);
    
    if (read_response(NULL))
        return -1;

    return 0;
}
