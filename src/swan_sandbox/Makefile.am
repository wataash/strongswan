# based on:
# src/charon-cmd/Makefile.am
# src/tpm_extendpcr/Makefile.am

bin_PROGRAMS = swan_sandbox

swan_sandbox_SOURCES = swan_sandbox.c swan_sandbox_charon.c

swan_sandbox.o :	$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-DIPSEC_CONFDIR=\"${sysconfdir}\" \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DIPSEC_PIDDIR=\"${piddir}\" \
	-DPLUGINS=\""${cmd_plugins}\""

swan_sandbox_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	$(PTHREADLIB) $(ATOMICLIB) $(DLLIB)
