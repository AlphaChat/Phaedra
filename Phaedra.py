#!/usr/bin/env python3

# Phaedra - vHost Management & Request Approval Bot
#
# Copyright (C) 2020-2025 Aaron M. D. Jones <aaron@alphachat.net>
#
# This bot matches vHost requests against the Public Suffix List
# (https://publicsuffix.org/learn/). It can automatically reject them
# (when the request matches and the user's control over the domain
# cannot be established) or activate them (when control is established).
# It can also advise staff to activate requests that don't match the
# list.
#
# This program will not function as-is without a custom module loaded
# into Atheme IRC Services. The module's sourcecode is located along-
# side this file in the source repository. The module is necessary to
# perform some up-front request validation (namely, that the vHost
# request must be DNS-legal) and forward the request to the bot,
# denying the request if the bot is not currently online.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import aiodns
import aiohttp
import argparse
import asyncio
import base64
import binascii
import email.utils
import hashlib
import hmac
import os
import publicsuffix2
import re
import signal
import sys

from AlphaChat.ConfigPydle import ConfigPydleClient
from datetime import datetime, timezone



def emu_httptime_to_timestamp(htime):

	return email.utils.parsedate_to_datetime(htime).timestamp()



def emu_timestamp_to_httptime(stamp):

	return email.utils.formatdate(timeval=stamp, localtime=False, usegmt=True)



class PhaedraClient(ConfigPydleClient):

	def __init__(self, *args, **kwargs):

		super().__init__(*args, **kwargs)

		self.request_expr       = re.compile('^VHOSTREQ ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+)$')
		self.resolver           = aiodns.DNSResolver(timeout=1, tries=3, domains=[], rotate=True)
		self.http_session       = None
		self.suffix_list        = None
		self.suffix_lock        = asyncio.Lock()

		self.acchannels.add(self.acconfig['log_channel'])
		self.acchannels.add(self.acconfig['oper_channel'])



	def compute_challenge_token(self, secret, netname, entity, account, suffix):

		# Entirely arbitrary derivation mechanics
		pk = f'netname={netname},entity={entity},account={account},suffix={suffix}'
		dk = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), pk.encode('utf-8'), 1000, dklen=42)
		tk = base64.b64encode(dk).decode('utf-8')

		return (netname + '-dcv.' + suffix, tk)



	def do_load_list(self, path):

		with open(path, 'r') as f:
			suffix_list_candidate = publicsuffix2.PublicSuffixList(psl_file=f, idna=True)
			if suffix_list_candidate.get_sld('foo.bar.baz.example.net', strict=True) == 'example.net':
				self.suffix_list = suffix_list_candidate
			else:
				raise Exception('Public Suffix List testcase failed')



	async def log_message(self, message):

		await self.message(self.acconfig['log_channel'], message)



	async def oper_message(self, message):

		await self.notice(self.acconfig['oper_channel'], message)



	async def update_list(self):

		while await asyncio.sleep(1, result=True):

			current_ts = int(datetime.now(tz=timezone.utc).timestamp())
			update_interval = self.acconfig['update_interval']
			await asyncio.sleep(update_interval - (current_ts % update_interval))

			async with self.suffix_lock:
				await self.do_update_list()



	async def do_update_list(self):

		headers = {}
		pslpath = self.acconfig['public_suffix_path']
		tmppath = pslpath + '.tmp'

		try:
			mtime = os.path.getmtime(pslpath)
			htime = emu_timestamp_to_httptime(mtime)
			headers['If-Modified-Since'] = htime
		except:
			pass

		try:
			if self.http_session is None:
				if 'proxy_url' in self.acconfig:
					self.http_session = aiohttp.ClientSession(proxy=self.acconfig['proxy_url'])
				else:
					self.http_session = aiohttp.ClientSession()

			async with self.http_session.get(self.acconfig['update_uri'], headers=headers) as resp:

				if resp.status == 304:
					if self.suffix_list is None:
						self.do_load_list(pslpath)
					return

				if resp.status != 200:
					raise Exception(f'Received HTTP response with status code ' \
					                f'{resp.status}; expected status codes 200 or 304')

				if not 'Last-Modified' in resp.headers:
					raise Exception(f'Received HTTP response without a Last-Modified header')

				with open(tmppath, 'wb') as f:
					while True:
						chunk = await resp.content.read(4096)
						if chunk:
							f.write(chunk)
						else:
							break

					f.flush()
					os.fsync(f.fileno())
					f.close()

				htime = resp.headers['Last-Modified']
				mtime = emu_httptime_to_timestamp(htime)
				os.utime(tmppath, (mtime, mtime))
				self.do_load_list(tmppath)
				os.replace(tmppath, pslpath)

			suffixcnt = len(self.suffix_list.tlds)

			await self.log_message(f'\x0303Updated Public Suffix List ' \
			                       f'(Last-Modified: {htime}) (Suffix Count: {suffixcnt})\x03')

		except Exception as e:
			await self.log_message(f'\x0304Exception {type(e)} while updating the ' \
			                       f'Public Suffix List: {str(e)}\x03')



	async def wmessage_header(self, nickname):

		await self.wmessage(nickname, f'[Automatic Message] Hello, {nickname}! You are receiving this ' \
		                              f'message because you just requested a vHost that matches the ' \
		                              f'Public Suffix List (https://publicsuffix.org/learn/). ' \
		                              f'Unfortunately, requests for vHosts on this network that match ' \
		                              f'the Public Suffix List (i.e. that could, either now, or in the ' \
		                              f'future, be a registered domain name) must pass domain control ' \
		                              f'validation.')



	async def wmessage_footer(self, nickname):

		await self.message(nickname, f'Please do not reply; messages to this service are not monitored.')
		await self.message(nickname, f'----------------------------------------------------------------')

		await self.raw(f'ACCEPT -{nickname}\r\n')



	async def approve_request(self, nickname, account, vhost, suffix):

		await self.message('HostServ', f'REJECT {account} SILENT')
		await self.message('NickServ', f'VHOST {account} ON {vhost} FORCE')

		await self.wmessage(nickname, f'Domain control validation for "{suffix}" was successful, ' \
		                              f'and your request for "{vhost}" has been approved.')

		await self.wmessage_footer(nickname)

		await self.oper_message(f'\x0303The request \x02{vhost}\x02 matches the Public Suffix List, and ' \
		                        f'domain control validation for \x02{account}\x02 succeeded! It has been ' \
		                        f'activated.\x03')



	async def reject_no_nameservers(self, nickname, account, vhost, suffix):

		await self.message('HostServ', f'REJECT {account} SILENT')

		await self.wmessage_header(nickname)

		await self.wmessage(nickname, f'However, I failed to validate your control over the ' \
		                              f'suffix "{suffix}", because I am unable to look up its ' \
		                              f'name servers, indicating that it probably does not yet ' \
		                              f'exist as a registered domain name. Therefore, domain ' \
		                              f'control validation cannot proceed, and so your request ' \
		                              f'has been rejected.')

		await self.wmessage_footer(nickname)

		await self.oper_message(f'\x0304The request \x02{vhost}\x02 matches the Public Suffix ' \
		                        f'List, and domain control validation for \x02{account}\x02 ' \
		                        f'failed! It has been rejected.\x03')



	async def reject_record_notfound(self, nickname, account, vhost, suffix, rrname, token):

		await self.message('HostServ', f'REJECT {account} SILENT')

		await self.wmessage_header(nickname)

		await self.wmessage(nickname, f'However, I failed to validate your control over the suffix ' \
		                              f'"{suffix}", because the expected DNS TXT record under it is ' \
		                              f'missing or invalid. Therefore, your request has been rejected. ' \
		                              f'If you do own or control this domain name, and you still wish ' \
		                              f'to request a vHost containing it, please create the following ' \
		                              f'DNS TXT record, wait a few minutes for your DNS provider to ' \
		                              f'put it into place, and then re-submit your request:')

		await self.message(nickname, f'Name: {rrname}')
		await self.message(nickname, f'Data: {token}')
		await self.message(nickname, None)

		await self.wmessage_footer(nickname)

		await self.oper_message(f'\x0304The request \x02{vhost}\x02 matches the Public Suffix ' \
		                        f'List, and domain control validation for \x02{account}\x02 ' \
		                        f'failed! It has been rejected.\x03')



	async def reject_exception(self, nickname, account, vhost, suffix):

		await self.message('HostServ', f'REJECT {account} SILENT')

		await self.wmessage_header(nickname)

		await self.message(nickname, f'However, I failed to validate your control over the suffix ' \
		                             f'"{suffix}", because of an internal error. Therefore, your ' \
		                             f'request has been rejected. The network staff have been ' \
		                             f'notified; please be patient, and do not re-submit your ' \
		                             f'request until told to do so.')

		await self.wmessage_footer(nickname)



	async def on_raw_001(self, message):

		await super().on_raw_001(message)

		async with self.suffix_lock:
			await self.add_ev_task(self.update_list())
			if self.suffix_list is None:
				await self.do_update_list()



	async def on_private_message(self, target, source, message):

		await super().on_private_message(target, source, message)

		if source != 'HostServ':
			return

		matches = self.request_expr.fullmatch(message)
		if not matches:
			return

		entity = matches.group(1)
		account = matches.group(2)
		nickname = matches.group(3)
		vhost = matches.group(4)
		suffix = None

		await self.oper_message(f'The user \x02{nickname}\x02 (account \x02{account}\x02) has ' \
		                        f'requested the vHost \x02{vhost}\x02.')

		if self.suffix_list is None:
			await self.oper_message(f'\x0304I am unable to match this request against the Public ' \
			                        f'Suffix List because I have failed to parse the list in the ' \
			                        f'past. \x02Please review the request manually.\x02\x03')
			return

		try:
			suffix = self.suffix_list.get_sld(vhost, strict=True)
			if suffix is None:
				await self.oper_message(f'\x0308It does not match the Public Suffix List; ' \
				                        f'please consider activating it.\x03')
				return
		except Exception as e:
			await self.oper_message(f'\x0304Exception while matching \x02{vhost}\x02 against the ' \
			                        f'Public Suffix List: {str(e)}\x03')
			return

		try:
			candidates = []
			try:
				results = await self.resolver.query(suffix, 'NS')
				if not isinstance(results, list):
					results = [results]
				for result in results:
					candidates.append(result.host)
			except aiodns.error.DNSError:
				await self.reject_no_nameservers(nickname, account, vhost, suffix)
				return

			nameservers = []
			candidates = list(set(candidates))
			for candidate in candidates:
				try:
					results = await self.resolver.query(candidate, 'AAAA')
					if not isinstance(results, list):
						results = [results]
					for result in results:
						nameservers.append(result.host)
				except aiodns.error.DNSError:
					pass
				try:
					results = await self.resolver.query(candidate, 'A')
					if not isinstance(results, list):
						results = [results]
					for result in results:
						nameservers.append(result.host)
				except aiodns.error.DNSError:
					pass

			nameservers = list(set(nameservers))
			if not len(nameservers):
				await self.reject_no_nameservers(nickname, account, vhost, suffix)
				return

			rrname, token = self.compute_challenge_token(self.acconfig['validator_secret'],
			                                             self.acconfig['validator_netname'],
			                                             entity, account, suffix)

			txt_resolver = aiodns.DNSResolver(timeout=1, tries=3, nameservers=nameservers, domains=[],
			                                  rotate=True)

			try:
				results = await txt_resolver.query(rrname, 'TXT')
				if not isinstance(results, list):
					results = [results]
				for result in results:
					if result.text == token:
						await self.approve_request(nickname, account, vhost, suffix)
						return
			except aiodns.error.DNSError:
				pass

			await self.reject_record_notfound(nickname, account, vhost, suffix, rrname, token)

		except Exception as e:
			await self.reject_exception(nickname, account, vhost, suffix)
			await self.oper_message(f'\x0304Exception while handling request for ' \
			                        f'\x02{account}\x02 (\x02{vhost}\x02): {str(e)}\x03')
			return



if __name__ == '__main__':

	default_config_keys = {
		'update_interval':      '7200',
	        'update_uri':           'https://publicsuffix.org/list/public_suffix_list.dat',
		'public_suffix_path':   'public_suffix_list.dat',
	}

	required_config_keys = [
		'log_channel',
		'oper_channel',
		'update_interval',
		'update_uri',
		'validator_netname',
		'validator_secret',
	]

	parser = argparse.ArgumentParser()
	parser.add_argument('--config', default='client.yaml')
	args = parser.parse_args()

	client = PhaedraClient(args.config, default_config_keys, required_config_keys)
	client.run()
	sys.exit(1)
