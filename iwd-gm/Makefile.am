
AM_MAKEFLAGS = --no-print-directory

ACLOCAL_AMFLAGS = -I build-aux

builtin_modules =
builtin_sources =

if EXTERNAL_ELL
ell_cflags = @ELL_CFLAGS@
ell_ldadd = @ELL_LIBS@
ell_dependencies =
ell_built_sources =
else
ell_cflags =
ell_ldadd = ell/libell-internal.la
ell_dependencies = $(ell_ldadd)
ell_built_sources = ell/internal ell/ell.h

noinst_LTLIBRARIES = ell/libell-internal.la

ell_headers = ell/util.h \
			ell/test.h \
			ell/strv.h \
			ell/utf8.h \
			ell/queue.h \
			ell/hashmap.h \
			ell/string.h \
			ell/settings.h \
			ell/main.h \
			ell/idle.h \
			ell/signal.h \
			ell/timeout.h \
			ell/io.h \
			ell/ringbuf.h \
			ell/log.h \
			ell/plugin.h \
			ell/checksum.h \
			ell/netlink.h \
			ell/genl.h \
			ell/dbus.h \
			ell/dbus-service.h \
			ell/dbus-client.h \
			ell/hwdb.h \
			ell/cipher.h \
			ell/random.h \
			ell/uintset.h \
			ell/base64.h \
			ell/pem.h \
			ell/tls.h \
			ell/uuid.h \
			ell/key.h \
			ell/pkcs5.h \
			ell/file.h \
			ell/dir.h \
			ell/net.h \
			ell/dhcp.h \
			ell/cert.h

ell_sources = ell/private.h \
			ell/missing.h \
			ell/util.c \
			ell/test.c \
			ell/strv.c \
			ell/utf8.c \
			ell/queue.c \
			ell/hashmap.c \
			ell/string.c \
			ell/settings.c \
			ell/main.c \
			ell/idle.c \
			ell/signal.c \
			ell/timeout.c \
			ell/io.c \
			ell/ringbuf.c \
			ell/log.c \
			ell/plugin.c \
			ell/checksum.c \
			ell/netlink-private.h \
			ell/netlink.c \
			ell/genl-private.h \
			ell/genl.c \
			ell/dbus-private.h \
			ell/dbus.c \
			ell/dbus-message.c \
			ell/dbus-util.c \
			ell/dbus-service.c \
			ell/dbus-client.c \
			ell/dbus-name-cache.c \
			ell/dbus-filter.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c \
			ell/siphash-private.h \
			ell/siphash.c \
			ell/hwdb.c \
			ell/cipher.c \
			ell/random.c \
			ell/uintset.c \
			ell/base64.c \
			ell/asn1-private.h \
			ell/pem.c \
			ell/tls-private.h \
			ell/tls.c \
			ell/tls-record.c \
			ell/uuid.c \
			ell/key.c \
			ell/pkcs5-private.h \
			ell/pkcs5.c \
			ell/file.c \
			ell/dir.c \
			ell/net.c \
			ell/dhcp-private.h \
			ell/dhcp.c \
			ell/dhcp-transport.c \
			ell/dhcp-lease.c \
			ell/cert-private.h \
			ell/cert.c

ell_libell_internal_la_SOURCES = $(ell_headers) $(ell_sources)
endif

bin_PROGRAMS =
libexec_PROGRAMS =
noinst_PROGRAMS =

if DBUS_POLICY
dbus_datadir = @DBUS_DATADIR@/dbus-1/system.d
dist_dbus_data_DATA =
endif

if SYSTEMD_SERVICE
systemd_unitdir = @SYSTEMD_UNITDIR@
systemd_unit_DATA =

dbus_busdir = @DBUS_BUSDIR@
dbus_bus_DATA =
endif

eap_sources = src/eap.c src/eap.h src/eap-private.h \
				src/eap-wsc.c src/eap-wsc.h \
				src/eap-md5.c \
				src/eap-tls.c \
				src/eap-ttls.c \
				src/eap-mschapv2.c src/eap-mschapv2.h \
				src/eap-sim.c \
				src/eap-aka.c \
				src/eap-peap.c \
				src/eap-gtc.c \
				src/eap-pwd.c \
				src/util.h src/util.c \
				src/crypto.h src/crypto.c \
				src/ecc.h src/ecc.c \
				src/wscutil.h src/wscutil.c \
				src/simutil.h src/simutil.c \
				src/simauth.h src/simauth.c \
				src/watchlist.h src/watchlist.c \
				src/eap-tls-common.h src/eap-tls-common.c \
				src/mschaputil.h src/mschaputil.c

if DAEMON
libexec_PROGRAMS += src/iwd

src_iwd_SOURCES = src/main.c linux/nl80211.h src/iwd.h \
					src/plugin.h src/plugin.c \
					src/netdev.h src/netdev.c \
					src/wiphy.h src/wiphy.c \
					src/device.h src/device.c \
					src/station.h src/station.c \
					src/ie.h src/ie.c \
					src/dbus.h src/dbus.c \
					src/mpdu.h src/mpdu.c \
					src/eapol.h src/eapol.c \
					src/eapolutil.h src/eapolutil.c \
					src/handshake.h src/handshake.c \
					src/scan.h src/scan.c \
					src/common.h src/common.c \
					src/agent.h src/agent.c \
					src/storage.h src/storage.c \
					src/network.h src/network.c \
					src/wsc.c \
					src/backtrace.h src/backtrace.c \
					src/knownnetworks.h \
					src/knownnetworks.c \
					src/rfkill.h src/rfkill.c \
					src/ftutil.h src/ftutil.c \
					src/ap.h src/ap.c \
					src/adhoc.h src/adhoc.c \
					src/sae.h src/sae.c \
					src/nl80211util.h src/nl80211util.c \
					src/ecdh.h src/ecdh.c \
					src/owe.h src/owe.c \
					$(eap_sources) \
					$(builtin_sources)
src_iwd_LDADD = $(ell_ldadd) -ldl
src_iwd_DEPENDENCIES = $(ell_dependencies)

if SIM_HARDCODED
builtin_modules += sim_hardcoded
builtin_sources += plugins/sim_hardcoded.c
endif

if OFONO
builtin_modules += ofono
builtin_sources += plugins/ofono.c
endif

if DBUS_POLICY
dist_dbus_data_DATA += src/iwd-dbus.conf
endif

if SYSTEMD_SERVICE
src_iwd_DEPENDENCIES += src/iwd.service

systemd_unit_DATA += src/iwd.service
dbus_bus_DATA += src/net.connman.iwd.service
endif
endif

if CLIENT
bin_PROGRAMS += client/iwctl

client_iwctl_SOURCES = client/main.c \
			client/adapter.c \
			client/agent.h client/agent.c \
			client/agent-manager.h client/agent-manager.c \
			client/ad-hoc.c \
			client/ap.c \
			client/command.h client/command.c \
			client/dbus-proxy.h client/dbus-proxy.c \
			client/device.h client/device.c \
			client/display.h client/display.c \
			client/known-networks.c \
			client/network.h client/network.c \
			client/properties.h client/properties.c \
			client/wsc.c client/station.c
client_iwctl_LDADD = $(ell_ldadd) -lreadline
endif

if MONITOR
bin_PROGRAMS += monitor/iwmon

monitor_iwmon_SOURCES = monitor/main.c linux/nl80211.h \
					monitor/nlmon.h monitor/nlmon.c \
					monitor/pcap.h monitor/pcap.c \
					monitor/display.h monitor/display.c \
					src/ie.h src/ie.c \
					src/wscutil.h src/wscutil.c \
					src/mpdu.h src/mpdu.c \
					src/util.h src/util.c \
					src/crypto.h src/crypto.c \
					src/watchlist.h src/watchlist.c \
					src/eapolutil.h src/eapolutil.c \
					src/handshake.h src/handshake.c
monitor_iwmon_LDADD = $(ell_ldadd)
endif

if WIRED
libexec_PROGRAMS += wired/ead

wired_ead_SOURCES = wired/main.c wired/ethdev.h wired/ethdev.c \
				wired/network.h wired/network.c \
				wired/dbus.h wired/dbus.c $(eap_sources)
wired_ead_LDADD = $(ell_ldadd)
wired_ead_DEPENDENCIES = $(ell_dependencies)

if DBUS_POLICY
dist_dbus_data_DATA += wired/ead-dbus.conf
endif

if SYSTEMD_SERVICE
wired_ead_DEPENDENCIES += wired/ead.service

systemd_unit_DATA += wired/ead.service
dbus_bus_DATA += wired/net.connman.ead.service
endif
endif

if HWSIM
bin_PROGRAMS += tools/hwsim

tools_hwsim_SOURCES = tools/hwsim.c src/mpdu.h \
					src/util.h src/util.c \
					src/storage.h src/storage.c \
					src/common.h src/common.c
tools_hwsim_LDADD = $(ell_ldadd)

if DBUS_POLICY
dist_dbus_data_DATA += tools/hwsim-dbus.conf
endif
endif

if TOOLS
noinst_PROGRAMS += tools/test-runner

tools_test_runner_SOURCES = tools/test-runner.c
tools_test_runner_LDADD = $(ell_ldadd)
endif

unit_tests = unit/test-cmac-aes \
		unit/test-hmac-md5 unit/test-hmac-sha1 unit/test-hmac-sha256 \
		unit/test-prf-sha1 unit/test-kdf-sha256 \
		unit/test-crypto unit/test-eapol unit/test-mpdu \
		unit/test-ie unit/test-ssid-to-utf8 unit/test-ssid-security \
		unit/test-arc4 unit/test-wsc unit/test-eap-mschapv2 \
		unit/test-eap-sim unit/test-ecc unit/test-sae unit/test-ecdh

if CLIENT
unit_tests += unit/test-client
endif


ell_pem_files = cert-ca-key.pem cert-client-key.pem cert-client-key-pkcs8.pem \
		cert-server-key.pem cert-server-key-pkcs8.pem \
		cert-ca.pem cert-client.pem cert-server.pem

if MAINTAINER_MODE
noinst_PROGRAMS += $(unit_tests)
noinst_DATA = ell/unit/test_data
endif

unit_test_eap_sim_SOURCES = unit/test-eap-sim.c \
		src/crypto.h src/crypto.c src/simutil.h src/simutil.c \
		src/ie.h src/ie.c \
		src/watchlist.h src/watchlist.c \
		src/eapol.h src/eapol.c \
		src/eapolutil.h src/eapolutil.c \
		src/handshake.h src/handshake.c \
		src/eap.h src/eap.c src/eap-private.h \
		src/util.h src/util.c \
		src/simauth.h src/simauth.c \
		src/eap-sim.c

unit_test_eap_sim_LDADD = $(ell_ldadd)

unit_test_cmac_aes_SOURCES = unit/test-cmac-aes.c \
					src/crypto.h src/crypto.c
unit_test_cmac_aes_LDADD = $(ell_ldadd)

unit_test_arc4_SOURCES = unit/test-arc4.c \
					src/crypto.h src/crypto.c

unit_test_arc4_LDADD = $(ell_ldadd)

unit_test_hmac_md5_SOURCES = unit/test-hmac-md5.c \
					src/crypto.h src/crypto.c
unit_test_hmac_md5_LDADD = $(ell_ldadd)

unit_test_hmac_sha1_SOURCES = unit/test-hmac-sha1.c \
					src/crypto.h src/crypto.c
unit_test_hmac_sha1_LDADD = $(ell_ldadd)

unit_test_hmac_sha256_SOURCES = unit/test-hmac-sha256.c \
					src/crypto.h src/crypto.c
unit_test_hmac_sha256_LDADD = $(ell_ldadd)

unit_test_prf_sha1_SOURCES = unit/test-prf-sha1.c \
					src/crypto.h src/crypto.c
unit_test_prf_sha1_LDADD = $(ell_ldadd)

unit_test_kdf_sha256_SOURCES = unit/test-kdf-sha256.c \
					src/crypto.h src/crypto.c
unit_test_kdf_sha256_LDADD = $(ell_ldadd)

unit_test_ie_SOURCES = unit/test-ie.c src/ie.h src/ie.c
unit_test_ie_LDADD = $(ell_ldadd)

unit_test_crypto_SOURCES = unit/test-crypto.c \
				src/crypto.h src/crypto.c
unit_test_crypto_LDADD = $(ell_ldadd)

unit_test_mpdu_SOURCES = unit/test-mpdu.c \
				src/mpdu.h src/mpdu.c \
				src/ie.h src/ie.c
unit_test_mpdu_LDADD = $(ell_ldadd)

unit_test_eapol_SOURCES = unit/test-eapol.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/watchlist.h src/watchlist.c \
				src/eapol.h src/eapol.c \
				src/eapolutil.h src/eapolutil.c \
				src/handshake.h src/handshake.c \
				src/eap.h src/eap.c src/eap-private.h \
				src/eap-tls.c src/eap-ttls.c \
				src/eap-md5.c src/util.c \
				src/eap-tls-common.h src/eap-tls-common.c \
				src/mschaputil.h src/mschaputil.c
unit_test_eapol_LDADD = $(ell_ldadd)

unit_test_ssid_to_utf8_SOURCES = src/util.h src/util.c \
				unit/test-ssid-to-utf8.c
unit_test_ssid_to_utf8_LDADD = $(ell_ldadd)

unit_test_ssid_security_SOURCES = unit/test-ssid-security.c src/ie.h src/ie.c \
				src/common.h src/common.c
unit_test_ssid_security_LDADD = $(ell_ldadd)

unit_test_wsc_SOURCES = unit/test-wsc.c src/wscutil.h src/wscutil.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/watchlist.h src/watchlist.c \
				src/eapol.h src/eapol.c \
				src/eapolutil.h src/eapolutil.c \
				src/handshake.h src/handshake.c \
				src/eap.h src/eap.c src/eap-private.h \
				src/util.h src/util.c \
				src/eap-wsc.h src/eap-wsc.c
unit_test_wsc_LDADD = $(ell_ldadd)

unit_test_eap_mschapv2_SOURCES = src/eap-mschapv2.h src/eap-mschapv2.c \
				src/eap.c src/eap.h src/eap-private.h \
				unit/test-eap-mschapv2.c
unit_test_eap_mschapv2_LDADD = $(ell_ldadd)

if CLIENT
unit_test_client_SOURCES = unit/test-client.c \
				client/adapter.c \
				client/agent.h client/agent.c \
				client/agent-manager.h client/agent-manager.c \
				client/command.h client/command.c \
				client/dbus-proxy.h client/dbus-proxy.c \
				client/display.h client/display.c \
				client/network.h client/network.c \
				client/properties.h client/properties.c
unit_test_client_LDADD = $(ell_ldadd) -lreadline
endif

unit_test_ecc_SOURCES = unit/test-ecc.c src/ecc.c src/ecc.h
unit_test_ecc_LDADD = $(ell_ldadd)

unit_test_sae_SOURCES = unit/test-sae.c \
				src/sae.h src/sae.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/handshake.h src/handshake.c \
				src/util.h src/util.c \
				src/ecc.h src/ecc.c
unit_test_sae_LDADD = $(ell_ldadd)

unit_test_ecdh_SOURCES = unit/test-ecdh.c \
				src/ecdh.h src/ecdh.c \
				src/ecc.h src/ecc.c
unit_test_ecdh_LDADD = $(ell_ldadd)
unit_test_ecdh_LDFLAGS = -Wl,-wrap,l_getrandom

TESTS = $(unit_tests)

manual_pages = doc/iwmon.1

if BUILD_DOCS
dist_man_MANS = $(manual_pages)
endif

EXTRA_DIST = src/genbuiltin src/iwd.service.in src/net.connman.iwd.service \
			wired/ead.service.in wired/net.connman.ead.service \
			doc/main.conf $(manual_pages:.1=.txt)

AM_CFLAGS = $(ell_cflags) -fvisibility=hidden

CLEANFILES = src/iwd.service wired/ead.service

DISTCHECK_CONFIGURE_FLAGS = --disable-dbus-policy --disable-systemd-service \
				--enable-sim-hardcoded \
				--enable-ofono \
				--enable-wired \
				--enable-hwsim \
				--enable-tools

DISTCLEANFILES = $(BUILT_SOURCES) $(unit_tests) $(manual_pages)

MAINTAINERCLEANFILES = Makefile.in configure config.h.in aclocal.m4

BUILT_SOURCES = $(ell_built_sources) src/builtin.h

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_headers) $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell/$$f ; \
		fi \
	done > $@

ell/ell.h: Makefile
	$(AM_V_at)echo -n > $@
	$(AM_V_GEN)for f in $(ell_headers) ; do \
		echo "#include <$$f>" >> $@ ; \
	done

ell/unit/test_data: Makefile
	$(AM_V_at)$(MKDIR_P) ell/unit
	$(AM_V_GEN)for f in $(ell_pem_files) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell/unit -f $(abs_srcdir)/../ell/unit/$$f ; \
		fi \
	done > $@

SED_PROCESS = $(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
		$(SED) -e 's,@libexecdir\@,$(libexecdir),g' \
		< $< > $@

%.service: %.service.in Makefile
	$(SED_PROCESS)

%.1: %.txt
	$(AM_V_GEN)$(A2X) --doctype manpage --format manpage $(srcdir)/$<

maintainer-clean-local:
	-rm -rf build-aux ell

src/builtin.h: src/genbuiltin config.status
	$(AM_V_at)$(MKDIR_P) $(@D)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@
