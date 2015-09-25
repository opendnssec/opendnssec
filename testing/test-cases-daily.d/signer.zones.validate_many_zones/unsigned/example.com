example.com.	86400	IN	SOA	ns1.example.com. postmaster.example.com. 2009060301 10800 3600 604800 86400
example.com.	86400	IN	NS	ns1.example.com.
example.com.	86400	IN	NS	ns2.example.com.
test.example.com. 86400   IN      NS      ns2.example.com.
test1.test.example.com. 86400   IN      NS      ns2.example.com.
example.com.	86400	IN	MX	10 mail.example.com.
example.com.	86400	IN	A	192.0.2.1
example.com.	86400	IN	AAAA	2001:db8:85a3::8a2e:370:7334
dyn.example.com.	86400	IN	NS	ns1.example.com.
dyn.example.com.	86400	IN	NS	ns2.example.com.
test.dyn.example.com.   86400   IN      NS      ns2.example.com.
ns1.example.com.	86400	IN	A	192.0.2.1
ns1.example.com.	86400	IN	SSHFP	2 1 6087cc210496cc48f2a6e43bfa511fa073b814e7
ns1.example.com.	86400	IN	SSHFP	1 1 c045b7b6a8a9ae162b4eeeaef3c418500c24e7f6
ns1.example.com.	86400	IN	AAAA	2001:db8:85a3::8a2e:370:7334
ns2.example.com.	86400	IN	A	192.0.2.1
test.example.com.	86400	IN	A	192.0.2.1
robot.example.com.	86400	IN	A	192.0.2.1
unsaid.example.com.	86400	IN	CNAME	ns1.example.com.
www.example.com.	86400	IN	CNAME	ns1.example.com.
mail.example.com.	86400	IN	A	192.0.2.1
mail.example.com.	86400	IN	AAAA	2001:db8:85a3::8a2e:370:7334
kom.example.com.	86400	IN	A	192.0.2.1
sklommon.example.com.	86400	IN	A	192.0.2.1
internet.example.com.	86400	IN	CNAME	ns1.example.com.
frukost.example.com.	86400	IN	CNAME	ns1.example.com.
tptest.example.com.	86400	IN	CNAME	ns1.example.com.
ant.example.com.	86400	IN	CNAME	ns1.example.com.
yahoo.example.com.	86400	IN	CNAME	ns1.example.com.
rset.example.com.	86400	IN	CNAME	ns1.example.com.
test2.example.com.	86400	IN	A	192.0.2.1
xbox.example.com.	86400	IN	A	192.0.2.1
tomatos.example.com.	86400	IN	A	192.0.2.1
tomato.example.com.	86400	IN	A	192.0.2.1
_sip._tcp.example.com.	86400	IN	SRV	0 0 5060 not.in.zone.
_sip._udp.example.com.	86400	IN	SRV	0 0 5060 not.in.zone.
example.com.	86400	IN	NAPTR	10 0 "s" "SIP+D2T" "" _sip._tcp.example.com.
example.com.	86400	IN	NAPTR	20 0 "s" "SIP+D2U" "" _sip._udp.example.com.
_jabber._tcp.example.com.	86400	IN	SRV	5 0 5269 ns1.example.com.
_xmpp-server._tcp.example.com.	86400	IN	SRV	5 0 5269 ns1.example.com.
_xmpp-client._tcp.example.com.	86400	IN	SRV	5 0 5222 ns1.example.com.
blopp.example.com.	86400	IN	A	192.0.2.1
comp.example.com.	86400	IN	A	192.0.2.1
comp.example.com.	86400	IN	AAAA	2001:db8:85a3::8a2e:370:7334
comp.example.com.	86400	IN	SSHFP	2 1 ddaa0e859d08a7d40a1ce8689c61f2138809ed7c
comp.example.com.	86400	IN	SSHFP	1 1 443b9dd1521add6a15d103392d0a43b7ad652ed3
comp-2.example.com.	86400	IN	A	192.0.2.1
comp-3.example.com.	86400	IN	A	192.0.2.1
comp-3.example.com.	86400	IN	AAAA	2001:db8:85a3::8a2e:370:7334
machine.example.com.	86400	IN	A	192.0.2.1
machine.example.com.	86400	IN	AAAA	2001:db8:85a3::8a2e:370:7334
machine.example.com.	86400	IN	SSHFP	1 1 414d496aeede5d48f8f735089eb09a055ad19d25
machine.example.com.	86400	IN	SSHFP	2 1 f09c935f7a6229ba8e0b1a3620c8b346d13b255e
machine-2.example.com.	86400	IN	A	192.0.2.1
machine-2.example.com.	86400	IN	AAAA	2001:db8:85a3::8a2e:370:7334
dnssec.example.com.	86400	IN	CNAME	comp.example.com.
kabinettet.example.com.	86400	IN	CNAME	ns1.example.com.
goto80.example.com.	86400	IN	CNAME	ns1.example.com.
link-1000.example.com.	86400	IN	AAAA	2001:db8:85a3::8a2e:370:7334
0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0         IN      PTR     ptr.example.com.
*.res.example.com.	86400	IN	TXT	"data"

