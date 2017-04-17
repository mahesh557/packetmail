# packetmail
This script reads IPs from arguments / Clipboard and does packetmail lookup for intel
* Contact Nathan Flower to get Packetmail API Key
* Configure PROXY details in code if script is called behind proxy
* Set PROXY_TEST = 'fail' if you don't use the script behind proxy

```
$perl packetmail.pl help
@author Uma Mahesh Padisetty
@intel lookup on packetmail.net
Usage:
This script reads IPs from arguments / Clipboard and does packetmail lookup for intel

>perl packetmail.pl 		       - Extracts IPs from clipboard and lookup packetmail intel
>perl packetmail.pl [ip1] [ip2] ....   - Lookup packetmail intel for given ips.
>perl packetmail.pl help          	- display usage


$perl packetmail.pl 
Checking Reputation for 3/3 IP
+-------------------+---------------------+-------------------------------------------------------------------------------------------------------------+
| Query(packetmail) | created_on          | Reputation                                                                                                  |
+-------------------+---------------------+-------------------------------------------------------------------------------------------------------------+
| 159.203.104.51    | 2016-01-26 16:39:59 | 2016-01-26 16:39:59                                                                                         |
|                   |                     |                                                                                                             |
|                   |                     | bad_ips_qmail-smtp                                                                                          |
|                   |                     | 	2017-01-27 20:28:09 / https://www.badips.com/get/list/qmail-smtp/0?age=12h                                 |
|                   |                     | 	badips.com listed in qmail-smtp list with a score threshold of zero                                        |
|                   |                     |                                                                                                             |
|                   |                     | blocklist_de_all                                                                                            |
|                   |                     | 	2017-01-23 20:37:53 / http://lists.blocklist.de/lists/all.txt                                              |
|                   |                     | 	159.203.104.51 All IP addresses that have attacked one of our customers/servers                            |
|                   |                     | in the last 48 hours                                                                                        |
|                   |                     |                                                                                                             |
|                   |                     | UCEPROTECT_Backscatter                                                                                      |
|                   |                     | 	2017-02-15 20:40:15 / http://wget-mirrors.uceprotect.net/rbldnsd-all/ips.backscatterer.org.gz              |
|                   |                     | 	159.203.104.51 Every IP which backscatters (Sending misdirected bounces or                                 |
|                   |                     | misdirected autoresponders or sender callouts) will be listed                                               |
|                   |                     |                                                                                                             |
|                   |                     | wikipedia_globalblocklist                                                                                   |
|                   |                     | 	2017-02-13 16:59:27 / http://en.m.wikipedia.org/w/index.php?title=Special:GlobalBlockList&offset=&limit=50 |
|                   |                     | 	159.203..0/16 This is a list of all global blocks that are currently in effect.                            |
|                   |                     | Some blocks are marked as locally disabled; this means that they apply                                      |
|                   |                     | on other sites, but a local administrator has decided to disable them on                                    |
|                   |                     | this wiki.                                                                                                  |
|                   |                     |                                                                                                             |
|                   |                     | manitu_nixspam                                                                                              |
|                   |                     | 	2017-02-22 16:48:38 / http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz                              |
|                   |                     | 	2017-02-22T17:36+0100 159.203.104.51 IP of spam senders and hash values of                                 |
|                   |                     | incoming spam                                                                                               |
|                   |                     |                                                                                                             |
|                   |                     | UCEPROTECT_Level_1                                                                                          |
|                   |                     | 	2017-04-09 09:49:09 / http://wget-mirrors.uceprotect.net/rbldnsd-all/dnsbl-1.uceprotect.net.gz             |
|                   |                     | 	159.203.104.51 Blocking Class: Conservative                                                                |
|                   |                     |                                                                                                             |
| 74.118.118.90     | 2017-03-25 09:17:07 | 2017-03-25 09:17:07                                                                                         |
|                   |                     |                                                                                                             |
|                   |                     | bad_ips_proftpd                                                                                             |
|                   |                     | 	2017-03-26 12:30:14 / https://www.badips.com/get/list/proftpd/0?age=12h                                    |
|                   |                     | 	badips.com listed in proftpd list with a score threshold of zero                                           |
|                   |                     |                                                                                                             |
| 173.59.51.152     | 2017-03-02 03:11:43 | 2017-03-02 03:11:43                                                                                         |
|                   |                     |                                                                                                             |
|                   |                     | abuseipdb_badips                                                                                            |
|                   |                     | 	2017-03-30 18:49:35 / https://www.abuseipdb.com/sitemap                                                    |
|                   |                     | 	173.59.51.152                                                                                              |
|                   |                     |                                                                                                             |
|                   |                     | bad_ips_sshd                                                                                                |
|                   |                     | 	2017-03-27 04:54:40 / https://www.badips.com/get/list/sshd/0?age=12h                                       |
|                   |                     | 	badips.com listed in sshd list with a score threshold of zero                                              |
|                   |                     |                                                                                                             |
|                   |                     | security_edu_badactors                                                                                      |
|                   |                     | 	2017-03-10 05:00:00 / REDACTED_PRIVATE_SOURCE                                                              |
|                   |                     | 	173.59.51.152,scanner,2017-03-10T05:00:00-0500,173.59.51.152,scanner,badactors:                            |
|                   |                     | 112 scan attemtps from netflow detected scanner over 4 hrs on port 22                                       |
|                   |                     |                                                                                                             |
|                   |                     | blocklist_de_all                                                                                            |
|                   |                     | 	2017-04-03 04:06:37 / http://lists.blocklist.de/lists/all.txt                                              |
|                   |                     | 	173.59.51.152 All IP addresses that have attacked one of our customers/servers                             |
|                   |                     | in the last 48 hours                                                                                        |
|                   |                     |                                                                                                             |
+-------------------+---------------------+-------------------------------------------------------------------------------------------------------------+

$perl packetmail.pl 159.203.104.51 74.118.118.90
Checking Reputation for 2/2 IP
+-------------------+---------------------+-------------------------------------------------------------------------------------------------------------+
| Query(packetmail) | created_on          | Reputation                                                                                                  |
+-------------------+---------------------+-------------------------------------------------------------------------------------------------------------+
| 159.203.104.51    | 2016-01-26 16:39:59 | 2016-01-26 16:39:59                                                                                         |
|                   |                     |                                                                                                             |
|                   |                     | bad_ips_qmail-smtp                                                                                          |
|                   |                     | 	2017-01-27 20:28:09 / https://www.badips.com/get/list/qmail-smtp/0?age=12h                                 |
|                   |                     | 	badips.com listed in qmail-smtp list with a score threshold of zero                                        |
|                   |                     |                                                                                                             |
|                   |                     | blocklist_de_all                                                                                            |
|                   |                     | 	2017-01-23 20:37:53 / http://lists.blocklist.de/lists/all.txt                                              |
|                   |                     | 	159.203.104.51 All IP addresses that have attacked one of our customers/servers                            |
|                   |                     | in the last 48 hours                                                                                        |
|                   |                     |                                                                                                             |
|                   |                     | UCEPROTECT_Backscatter                                                                                      |
|                   |                     | 	2017-02-15 20:40:15 / http://wget-mirrors.uceprotect.net/rbldnsd-all/ips.backscatterer.org.gz              |
|                   |                     | 	159.203.104.51 Every IP which backscatters (Sending misdirected bounces or                                 |
|                   |                     | misdirected autoresponders or sender callouts) will be listed                                               |
|                   |                     |                                                                                                             |
|                   |                     | wikipedia_globalblocklist                                                                                   |
|                   |                     | 	2017-02-13 16:59:27 / http://en.m.wikipedia.org/w/index.php?title=Special:GlobalBlockList&offset=&limit=50 |
|                   |                     | 	159.203..0/16 This is a list of all global blocks that are currently in effect.                            |
|                   |                     | Some blocks are marked as locally disabled; this means that they apply                                      |
|                   |                     | on other sites, but a local administrator has decided to disable them on                                    |
|                   |                     | this wiki.                                                                                                  |
|                   |                     |                                                                                                             |
|                   |                     | manitu_nixspam                                                                                              |
|                   |                     | 	2017-02-22 16:48:38 / http://www.dnsbl.manitu.net/download/nixspam-ip.dump.gz                              |
|                   |                     | 	2017-02-22T17:36+0100 159.203.104.51 IP of spam senders and hash values of                                 |
|                   |                     | incoming spam                                                                                               |
|                   |                     |                                                                                                             |
|                   |                     | UCEPROTECT_Level_1                                                                                          |
|                   |                     | 	2017-04-09 09:49:09 / http://wget-mirrors.uceprotect.net/rbldnsd-all/dnsbl-1.uceprotect.net.gz             |
|                   |                     | 	159.203.104.51 Blocking Class: Conservative                                                                |
|                   |                     |                                                                                                             |
| 74.118.118.90     | 2017-03-25 09:17:07 | 2017-03-25 09:17:07                                                                                         |
|                   |                     |                                                                                                             |
|                   |                     | bad_ips_proftpd                                                                                             |
|                   |                     | 	2017-03-26 12:30:14 / https://www.badips.com/get/list/proftpd/0?age=12h                                    |
|                   |                     | 	badips.com listed in proftpd list with a score threshold of zero                                           |
|                   |                     |                                                                                                             |
+-------------------+---------------------+-------------------------------------------------------------------------------------------------------------+
