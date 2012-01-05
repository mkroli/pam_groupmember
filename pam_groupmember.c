/***************************************************************************
 *   Copyright (C) 2008 by Michael Krolikowski <mkroli@yahoo.de>           *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, version 2 of the License.               *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/


#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <sys/syslog.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#include "config.h"

#ifndef DEBUG
#define DEBUG 0
#endif

/*
 * Returns 1 if a string contains only numbers, otherwise 0.
 */
static int is_uint (const char* str)
{
	int i = 0;

	while (str[i])
	{
		if (str[i] < '0' || str[i] > '9')
		{
			return 0;
		}
		i++;
	}

	return 1;
}

/*
 * Searches for a user which name equals user or which uid
 * is atoi(user).
 */
static struct passwd* get_passwd (const char* user)
{
	struct passwd* pwd;

	if (!user)
		return 0;

	setpwent ();
	if (is_uint (user))
	{
		pwd = getpwuid (atoi (user));
	}
	else
	{
		pwd = getpwnam (user);
	}
	endpwent ();
	return pwd;
}

/*
 * Searches for a group which name equals group or which gid
 * is atoi(gid).
 */
static struct group* get_group (const char* group)
{
	struct group* grp;

	if (!group)
		return 0;

	setgrent ();
	if (is_uint (group))
	{
		grp = getgrgid (atoi (group));
	}
	else
	{
		grp = getgrnam (group);
	}
	endgrent ();
	return grp;
}

/*
 * Checks if user uid is in group gid.
 * Returns 1 if user is in the group, otherwise 0.
 */
static int user_in_group (const struct passwd* pwd, const struct group* grp)
{
	int i = 0;

	if (!pwd || !grp)
	{
		return 0;
	}

	/* check if gid is the users group */
	if (pwd->pw_gid == grp->gr_gid)
	{
		return 1;
	}

	/* check if the user is member of the group gid */
	while (grp->gr_mem[i])
	{
		if (get_passwd (grp->gr_mem[i]))
		{
			return 1;
		}
		i++;
	}

	return 0;
}

PAM_EXTERN int pam_sm_acct_mgmt (pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	struct group* grp;
	struct passwd* pwd;
	char* user;
	int i;

	/* get user */
	i = pam_get_user (pamh, (const char**)(&user), 0);
	if (i != PAM_SUCCESS)
	{
#if DEBUG
		syslog (LOG_DEBUG, "(pam_groupmember) user not known");
#endif
		return i;
	}
	pwd = get_passwd (user);

	for (i=0; i<argc; i++)
	{
		grp = get_group (argv[i]);
		if (user_in_group (pwd, grp))
		{
#if DEBUG
			syslog (LOG_DEBUG, "(pam_groupmember) user %s in group %s", pwd->pw_name, grp->gr_name);
#endif
			return PAM_SUCCESS;
		}
	}

#if DEBUG
	syslog (LOG_DEBUG, "(pam_groupmember) no group matched for user %s", pwd->pw_name);
#endif
	return PAM_PERM_DENIED;
}

#ifdef PAM_STATIC
struct pam_module _pam_groupmember_modstruct = {
	"pam_groupmember",
	0,
	0,
	pam_sm_acct_mgmt,
	0,
	0,
	0
};
#endif

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY ("pam_groupmember");
#endif
