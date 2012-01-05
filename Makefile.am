moduledir = @PAM_MODDIR@
module_LTLIBRARIES = pam_groupmember.la

man_MANS = pam_groupmember.8

pam_groupmember_la_SOURCES = pam_groupmember.c
pam_groupmember_la_LIBADD  = -lpam
pam_groupmember_la_LDFLAGS = -module -avoid-version

install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/pam_groupmember.la;
