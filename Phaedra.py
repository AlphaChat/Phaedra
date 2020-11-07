#!/usr/bin/python3

# Phaedra - vHost Management & Request Approval Bot
#
# Copyright (C) 2020 Aaron M. D. Jones <aaron@alphachat.net>
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

from AlphaChat import configpydle
from datetime import datetime, timezone
from publicsuffixlist import PublicSuffixList

import aiodns
import aiohttp
import asyncio
import base64
import binascii
import email.utils
import hashlib
import hmac
import os
import re
import signal
import sys
import textwrap

PSLURI = 'https://publicsuffix.org/list/public_suffix_list.dat'



def httptime_to_timestamp(htime):

	return email.utils.parsedate_to_datetime(htime).timestamp()



def timestamp_to_httptime(stamp):

	return email.utils.formatdate(timeval=stamp, localtime=False, usegmt=True)



class Client(configpydle.Client):

	def __init__(self, *args, eventloop=None, **kwargs):

		super().__init__(*args, eventloop=eventloop, **kwargs)

		self.eventloop      = eventloop
		self.http_session   = aiohttp.ClientSession()
		self.request_expr   = re.compile('^VHOSTREQ ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+)$')
		self.resolver       = aiodns.DNSResolver(timeout=1, tries=3, domains=[], rotate=True,
		                                         loop=eventloop)
		self.suffix_list    = None
		self.text_wrapper   = textwrap.TextWrapper(width=64, expand_tabs=False, tabsize=1,
		                                           replace_whitespace=True, drop_whitespace=True)
		self.update_lock    = asyncio.Lock()



	async def check_membership(self):

		while self.connected:

			await asyncio.sleep(0.1)
			if not self.autoperform_done:
				continue

			if not self.in_channel(self.phcfg['log_channel']):
				await self.join(self.phcfg['log_channel'])

			if not self.in_channel(self.phcfg['oper_channel']):
				await self.join(self.phcfg['oper_channel'])



	async def update_list(self):

		while self.connected:

			await asyncio.sleep(0.1)
			if not self.autoperform_done:
				continue

			current_ts = int(datetime.now(tz=timezone.utc).timestamp())
			update_interval = self.phcfg['update_interval']
			await asyncio.sleep(update_interval - (current_ts % update_interval))
			while self.connected and not self.in_channel(self.phcfg['log_channel']):
				# The check_membership() task above will take care of this
				await asyncio.sleep(0.1)

			async with self.update_lock:
				if self.connected:
					try:
						await self.do_update_list()
					except Exception as e:
						await self.log_message(f'\x0304Exception while updating and/or ' \
						                       f'parsing the Public Suffix List: ' \
						                       f'{str(e)}\x03')



	async def sigterm_handler(self):

		if self.connected:
			await self.quit('Received SIGTERM')



	async def on_connect(self):

		await super().on_connect()

		async with self.update_lock:
			try:
				await self.do_update_list()
			except Exception as e:
				await self.log_message(f'\x0304Exception while updating and/or parsing the ' \
				                       f'Public Suffix List: {str(e)}\x03')

		self.eventloop.add_signal_handler(signal.SIGTERM,
		                                  lambda self=self: asyncio.create_task(self.sigterm_handler()))



	async def on_join(self, channel, user):

		await super().on_join(channel, user)

		if self.is_same_channel(channel, self.phcfg['log_channel']):
			return

		if self.is_same_channel(channel, self.phcfg['oper_channel']):
			return

		await self.part(channel)



	async def on_private_message(self, target, source, message):

		await super().on_private_message(target, source, message)

		if not source == self.phcfg['hostserv_nickname']:
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
			suffix = self.suffix_list.privatesuffix(vhost)
		except Exception as e:
			await self.oper_message(f'\x0304Exception while matching \x02{vhost}\x02 against the ' \
			                        f'Public Suffix List: {str(e)}\x03')
			return

		if suffix is None:
			await self.oper_message(f'\x0308It does not match the Public Suffix List; ' \
			                        f'please consider activating it.\x03')
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
				await self.reject(nickname, entity, account, vhost, suffix, False, False)
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
				await self.reject(nickname, entity, account, vhost, suffix, False, False)
				return

			rrname, token = self.compute_challenge_token(self.phcfg['validator_secret'],
			                                             self.phcfg['validator_netname'],
			                                             entity, account, suffix)

			txt_resolver = aiodns.DNSResolver(timeout=1, tries=3, nameservers=nameservers, domains=[],
			                                  rotate=True, loop=self.eventloop)

			try:
				results = await txt_resolver.query(rrname, 'TXT')
				if not isinstance(results, list):
					results = [results]
				for result in results:
					if result.text == token:
						await self.approve(nickname, entity, account, vhost, suffix)
						return
			except aiodns.error.DNSError:
				pass

			await self.reject(nickname, entity, account, vhost, suffix, True, False, rrname, token)

		except Exception as e:
			await self.oper_message(f'\x0304Exception while handling request for ' \
			                        f'\x02{account}\x02/\x02{vhost}\x02: {str(e)}\x03')
			await self.reject(nickname, entity, account, vhost, suffix, False, True)
			return



	def compute_challenge_token(self, secret, netname, entity, account, suffix):

		# Entirely arbitrary derivation mechanics
		pk = f'netname={netname},entity={entity},account={account},suffix={suffix}'
		dk = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), pk.encode('utf-8'), 1000, dklen=42)
		tk = base64.b64encode(dk).decode('utf-8')

		return (netname + '-dcv.' + suffix, tk)



	async def do_update_list(self):

		headers = {}
		pslpath = self.phcfg['public_suffix_path']
		tmppath = pslpath + '.tmp'

		try:
			mtime = os.path.getmtime(pslpath)
			htime = timestamp_to_httptime(mtime)
			headers['If-Modified-Since'] = htime
		except:
			pass

		async with self.http_session.get(PSLURI, headers=headers) as resp:
			if resp.status == 304:
				if not self.suffix_list:
					with open(pslpath, 'rb') as f:
						PSL = PublicSuffixList(source=f, accept_unknown=False, only_icann=False)
						if PSL.privatesuffix('foo.bar.baz.example.net') == 'example.net':
							self.suffix_list = PSL
						else:
							raise Exception('Testcase failed')
			else:
				if resp.status != 200:
					raise Exception(f'Received HTTP response with status code {resp.status}; ' \
					                f'expected status code 200')

				if not 'Last-Modified' in resp.headers:
					raise Exception(f'Received HTTP response without a Last-Modified header')

				with open(tmppath, 'wb') as f:
					while True:
						chunk = await resp.content.read(1024)
						if chunk:
							f.write(chunk)
						else:
							break

					f.flush()
					os.fsync(f.fileno())
					f.close()

				htime = resp.headers['Last-Modified']
				mtime = httptime_to_timestamp(htime)
				os.utime(tmppath, (mtime, mtime))

				with open(tmppath, 'rb') as f:
					PSL = PublicSuffixList(source=f, accept_unknown=False, only_icann=False)
					if PSL.privatesuffix('foo.bar.baz.example.net') == 'example.net':
						self.suffix_list = PSL
					else:
						raise Exception('Testcase failed')

				os.replace(tmppath, pslpath)
				await self.log_message(f'\x0303Updated Public Suffix List (Last-Modified: ' \
				                       f'"{htime}")\x03')



	async def message(self, target, message, wrap=True):

		if message == '':
			await super().message(target, ' ')
			return

		if not wrap:
			await super().message(target, message)
			return

		await super().message(target, ' ')
		for line in self.text_wrapper.wrap(message):
			await super().message(target, line)



	async def log_message(self, message):

		await super().message(self.phcfg['log_channel'], message)



	async def oper_message(self, message):

		await self.notice(self.phcfg['oper_channel'], message)



	async def approve(self, nickname, entity, account, vhost, suffix):

		await super().message(self.phcfg['hostserv_nickname'], f'ACTIVATE {account}')

		await self.oper_message(f'\x0303The request \x02{vhost}\x02 matches the Public Suffix List, and ' \
		                        f'domain control validation for \x02{account}\x02 succeeded! It has been ' \
		                        f'activated.\x03')

		await self.message(nickname, f'[Automatic Message] Hello, {nickname}! You are receiving this ' \
		                             f'message because you just requested a vHost ("{vhost}") that ' \
		                             f'matches the Public Suffix List (https://publicsuffix.org/learn/). ' \
		                             f'Domain control validation for "{suffix}" was successful, and your ' \
		                             f'request has been automatically activated.')
		await self.message(nickname, f'Please do not reply; messages to this service are not monitored.')
		await self.message(nickname, f'----------------------------------------------------------------',
		                             wrap=False)

		await self.raw(f'ACCEPT -{nickname}\r\n')



	async def reject(self, nickname, entity, account, vhost, suffix, got_nameservers, got_exception,
	                       rrname=None, token=None):

		await super().message(self.phcfg['hostserv_nickname'], f'REJECT {account} SILENT')

		if not got_exception:
			await self.oper_message(f'\x0304The request \x02{vhost}\x02 matches the Public Suffix ' \
			                        f'List, and domain control validation for \x02{account}\x02 ' \
			                        f'failed! It has been rejected.\x03')

		await self.message(nickname, f'[Automatic Message] Hello, {nickname}! You are receiving this ' \
		                             f'message because you just requested a vHost ("{vhost}") that ' \
		                             f'matches the Public Suffix List (https://publicsuffix.org/learn/). ' \
		                             f'Unfortunately, requests for vHosts on this network that match ' \
		                             f'the Public Suffix List (i.e. that could, either now, or in the ' \
		                             f'future, be a registered domain name) must pass domain control ' \
		                             f'validation.')

		if got_exception:
			await self.message(nickname, f'However, I failed to validate your control of the suffix ' \
			                             f'"{suffix}", because of an internal error. Therefore, your ' \
			                             f'request has been rejected. The network staff have been ' \
			                             f'notified; please be patient, and do not re-submit your ' \
			                             f'request until told to do so.')
		elif got_nameservers:
			await self.message(nickname, f'However, I failed to validate your control of the suffix ' \
			                             f'"{suffix}", because the expected DNS TXT record under it ' \
			                             f'is missing or invalid. Therefore, your request has been ' \
			                             f'rejected. If you do own or control this domain name, and ' \
			                             f'you still wish to request a vHost containing it, please ' \
			                             f'create the following DNS TXT record, wait a few minutes ' \
			                             f'(!), and then re-submit your request:')
			await self.message(nickname, f'')
			await self.message(nickname, f'  Name: {rrname}', wrap=False)
			await self.message(nickname, f'  Data: {token}', wrap=False)
		else:
			await self.message(nickname, f'However, I failed to validate your control of the suffix ' \
			                             f'"{suffix}", because I am unable to look up its name ' \
			                             f'servers, indicating that it probably does not (yet) exist ' \
			                             f'as a registered domain name. Therefore, domain control ' \
			                             f'validation cannot proceed, and so your request has been ' \
			                             f'rejected.')

		await self.message(nickname, f'Please do not reply; messages to this service are not monitored.')
		await self.message(nickname, f'----------------------------------------------------------------',
		                             wrap=False)

		await self.raw(f'ACCEPT -{nickname}\r\n')



async def main():

	required_config_keys = [
		'hostserv_nickname',
		'log_channel',
		'oper_channel',
		'public_suffix_path',
		'update_interval',
		'validator_netname',
		'validator_secret',
	]

	try:
		eventloop = asyncio.get_running_loop()
		client = Client(path='client.cfg', eventloop=eventloop, required_config_keys=required_config_keys)
		await client.connect()
		await asyncio.gather(client.check_membership(), client.update_list(), return_exceptions=True)
	except Exception as e:
		print(f'Exception: {str(e)}', file=sys.stderr)
		return



if __name__ == '__main__':
	asyncio.run(main())
	sys.exit(1)
