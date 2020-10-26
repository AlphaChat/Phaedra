/*
 * SPDX-License-Identifier: ISC
 * SPDX-URL: https://spdx.org/licenses/ISC.html
 *
 * Copyright (C) 2020 Aaron M. D. Jones <aaron@alphachat.net>
 */

#include <atheme.h>

#define INVALID_VHOST_REQ_THISNET "Invalid vHost request: vHosts on this network %s"

static struct service *hostsvs = NULL;
static unsigned int req_intvl = 0;
static char *mgmt_bot_nick = NULL;

static void
host_request_hook(struct hook_host_request *const restrict hdata)
{
	if (! (hdata && hdata->host && hdata->si && hdata->si->smu && hdata->target))
	{
		(void) slog(LG_ERROR, "%s: one or more required hook parameters is missing (BUG!)", MOWGLI_FUNC_NAME);

		hdata->approved++;
		return;
	}

	const struct metadata *const md = metadata_find(hdata->si->smu, "private:usercloak-timestamp");
	const char *const vhost = hdata->host;
	const size_t vhostlen = strlen(vhost);
	bool contains_period = false;
	struct user *mgmt_bot = NULL;

	if (req_intvl && md)
	{
		errno = 0;
		char *endp = NULL;
		const unsigned long ret = strtoul(md->value, &endp, 10);

		if (! (errno || (endp && *endp) || ret == ULONG_MAX || (unsigned int)(CURRTIME - ret) >= req_intvl))
		{
			(void) command_fail(hdata->si, fault_badparams,
			                    _("You must wait at least \2%u\2 days between changes to your vHost."),
			                    (req_intvl / SECONDS_PER_DAY));
			hdata->approved++;
			return;
		}
	}

	if (vhost[0] == '.' || vhost[0] == '-' || vhost[vhostlen - 1] == '.' || vhost[vhostlen - 1] == '-')
	{
		(void) command_fail(hdata->si, fault_badparams, INVALID_VHOST_REQ_THISNET,
		                    "must not begin or end with a period (.) or hyphen (-)");
		hdata->approved++;
	}

	for (const char *p = vhost; *p; p++)
	{
		if (! ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
		       (*p >= '0' && *p <= '9') || (*p == '-' || *p == '.')))
		{
			(void) command_fail(hdata->si, fault_badparams, INVALID_VHOST_REQ_THISNET,
			                    "must consist entirely of characters in the ranges "
			                    "[A-Z], [a-z], [0-9], '-', '.'");
			hdata->approved++;
		}

		if (*p == '.')
		{
			contains_period = true;

			if (p[1] == '.')
			{
				(void) command_fail(hdata->si, fault_badparams, INVALID_VHOST_REQ_THISNET,
				                    "must not contain consecutive periods (..)");
				hdata->approved++;
			}
			if (p[1] == '-' || (p > vhost && p[-1] == '-'))
			{
				(void) command_fail(hdata->si, fault_badparams, INVALID_VHOST_REQ_THISNET,
				                    "must not contain labels that begin or end with a hyphen (-)");
				hdata->approved++;
			}
		}
	}

	if (! contains_period)
	{
		(void) command_fail(hdata->si, fault_badparams, INVALID_VHOST_REQ_THISNET,
		                    "must contain at least one period (.)");
		hdata->approved++;
	}

	if (mgmt_bot_nick && *mgmt_bot_nick && ! (mgmt_bot = user_find_named(mgmt_bot_nick)))
	{
		(void) command_fail(hdata->si, fault_nochange, "Your vHost request cannot be processed at this time "
		                                               "because the bot that manages them is not online.");
		hdata->approved++;
	}

	if (hdata->approved)
		return;

	if (mgmt_bot)
		(void) msg(hostsvs->nick, mgmt_bot->nick, "VHOSTREQ %s %s %s %s", entity(hdata->si->smu)->id,
		           entity(hdata->si->smu)->name, hdata->target, hdata->host);
}

static void
mod_init(struct module *const restrict m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "hostserv/main")
	MODULE_TRY_REQUEST_DEPENDENCY(m, "hostserv/request")

	if (! (hostsvs = service_find("hostserv")))
	{
		(void) slog(LG_ERROR, "%s: service_find() for HostServ failed!", m->name);

		m->mflags |= MODFLAG_FAIL;
		return;
	}

	(void) add_dupstr_conf_item("MANAGEMENT_BOT", &hostsvs->conf_table, 0, &mgmt_bot_nick, NULL);
	(void) add_duration_conf_item("REQUEST_INTERVAL", &hostsvs->conf_table, 0, &req_intvl, "d", 0);
	(void) hook_add_host_request(&host_request_hook);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	(void) del_conf_item("MANAGEMENT_BOT", &hostsvs->conf_table);
	(void) del_conf_item("REQUEST_INTERVAL", &hostsvs->conf_table);
	(void) hook_del_host_request(&host_request_hook);
}

VENDOR_DECLARE_MODULE_V1("alphachat/vhost_restrictions", MODULE_UNLOAD_CAPABILITY_RELOAD_ONLY,
                         "AlphaChat IRC Network <https://www.alphachat.net/>")
