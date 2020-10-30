# Phaedra
AlphaChat's vHost Request Management & Approval Bot

---

This is a Python asyncio script (using the [Pydle IRC Client Framework](https://pydle.readthedocs.io/en/stable/)) to
take vHost requests from a custom [Atheme IRC Services](https://github.com/atheme/atheme/) module (also included in
this repository) and match them against Mozilla's [Public Suffix List](https://publicsuffix.org/learn/).

vHost requests that match this list (e.g. `foo.bar.baz.example.org` matches because `org` is on the list) are handled
by domain control validation. This consists of taking the private suffix (`example.org` for the previous example),
prepending the IRC-network-specific name to it (e.g. `foonet-dcv.example.org` for an IRC network called `FooNet`),
and requiring the user to create a DNS TXT record at that name with a precomputed token as its value.

This token is computed using:

1) A predefined secret of arbitrary length (configured in `client.cfg`)
2) The network's name (`alphachat` -- also configured in `client.cfg`)
3) The services account entity ID (`AAAAAABEA`)
4) The services account name (`Aaron`)
5) The private suffix in question (`example.org`)

This ensures that if the user changes their account name, or their account expires and another person subsequently
registers an account with the same name, that a subsequent vHost request for anything under the same private suffix
will not be automatically approved, even if the old token is still in place. It also ensures that should an IRC
network cease functioning, and someone else creates a new network in its place, that all pre-existing tokens are
also invalid, because the new network will not have the same predefined secret.

Private suffixes that do not have nameservers (e.g. that could be real, registered domain names, but aren't) are
automatically rejected, because it is not possible to proceed with domain control validation. Private suffixes that
do have nameservers will be checked for the token above; if the token is present, the request is automatically
approved, and if it is absent, the request is automatically rejected.

Regardless of which of the preceeding 3 scenarios is actually the case, the user making the request will receive a
message explaining what is happening, and if it is possible to proceed, instructions for doing so. There will be no
message to the user for requests that do not match the Public Suffix List.

---

GitHub Issues is disabled for this repository. There is no support provided for this software.
