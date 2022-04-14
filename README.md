# Laika BOSS: Object Scanning System
Laika is an object scanner and intrusion detection system that strives to achieve the following goals:

+ **Scalable**
	+ Work across multiple systems
	+ High volume of input from many sources
+ **Flexible**
	+ Modular architecture
	+ Highly configurable dispatching and dispositioning logic
	+ Tactical code insertion (without needing restart)
+ **Verbose**
	+ Generate more metadata than you know what to do with

Each scan does three main actions on each object:
+ **Extract child objects**

	Some objects are archives, some are wrappers, and others are obfuscators. Whatever the case may be, find children objects that should be scanned recursively by extracting them out.


+ **Mark flags**

	Flags provide a means for dispositioning objects and for pivoting on future analysis.


+ **Add metadata**

	Discover as much information describing the object for future analysis.

**Whitepaper can be found @ [http://lockheedmartin.com/us/what-we-do/information-technology/cybersecurity/laika-boss.html](http://lockheedmartin.com/us/what-we-do/information-technology/cybersecurity/laika-boss.html)**

## Components
Laika is composed of the following pieces:

+ **Framework** (laika.py)

	This is the core of Laika BOSS. It includes the object model and the dispatching logic.

+ **laikadq**

	This piece contains the code for running Laika as a deamon, which uses redis as a work queue.

+ **laikad**

	This piece contains the code for running Laika as a deamonized, networked service using the ZeroMQ broker.  (This fork does not use this component - so modifications are not as tested.)

+ **cloudscan**

	A command-line client for sending a local system file to a running service instance of Laika (laikad).

+ **laikatest**
    A test framework for modules, run `./laikatest.py` to run all tests in the `tests` directory. Tests for some modules are included.

+ **laikarestd**
    This piece is an interface for submitting scans through a rest API. It also includes a web GUI for accessing scans stored in S3 buckets (in conjunction with the SUBMIT_STORAGE_S# module).


+ **laikacollector**
    This is a daemonized script for monitoring a directory and submitting files that are placed in it into a redis work queue (in conjunction with laikadq, which takes jobs out of redis and processes them).

+ **laikamail**
The Laika BOSS mail server can replace sendmail or postfix (and laikamilter) if you only run on copies of email and not inline. It is much simpler to manage.
```
+----------------+             +---------------+             +----------------+
|                | local disk  |               |             |                |
|    laikamail   +------------->laikacollector +------------>|     redis      |
|                |             |               |             |                |
+----------------+             +---------------+             +----------------+

             +-----------+
             |           |
<------------> laikadq 1 +
             |           |
             +-----------+

             +-----------+
             |           |
<------------> laikadq 2 +
             |           |
             +-----------+

             +-----------+
             |           |
<------------> laikadq N +
             |           |
             +-----------+

```

+ **modules**

	The scan itself is composed of the running of modules. Each module is its own program that focuses on a particular sub-component of the overall file analysis.

## Getting Started
The Laika BOSS installation scripts have only been tested on Ubuntu 18.04 (vm or docker image). The upstream LM version has been tested on the latest versions of CentOS and Ubuntu LTS

+ Writing new modules
See the EXPLODE\_HELLOWORLD module (in `laikaboss/modules/explode_helloworld.py`) for an example of how to write a module.

#### running LB
From the directory containing the framework code, you may run the standalone scanner, laika.py against any file you choose. If you move this file from this directory you'll have to specify various config locations. By default it uses the configurations in the ./etc directory.

We recommend using [jq](http://stedolan.github.io/jq/) to parse Laika output.

##### Licensing
The Laika framework and associated modules are released under the terms of the Apache 2.0 license.

##### config abstraction
1. Download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
1. mkdir -p /etc/laikaboss/modules/geoip/
1. Put the geoip db at the location /etc/laikaboss/modules/geoip/GeoLite2-City.mmdb 
   (the docker compose will mount the /etc/laikaboss/modules/geoip directory into the container)
1. Hand edit <laikaboss src>/etc/dist/laika_cluster.conf including all site specific changes
   Make sure you uncomment the hostname, and cluster hostnames and set the values appropriately
   hostname=blah.example.com
##### Quick install for cluster configuration
###### Prereqs
1. Download the laikaboss source repo 
1. install python3 package
1. install pip for python3
1. pip3 install secrets future

####### Install
1. Create local directories and accounts by calling
   (laikaboss src)/setup-host.sh
1. Download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
1. Put the file at location /etc/laikaboss/modules/geoip/GeoLite2-City.mmdb
1. Hand edit (laikaboss src)/etc/dist/laika_cluster.conf including all site specific changes
   In Docker make sure you uncomment the hostname and set hostname

   hostname = lbhost.example.com
   laika_head_node_short = lbhost
   laika_head_node = lbhost.example.com

    ```
    ldap_uri=ldaps://ldap.example.com:636
    ldap_account_base=ou=people,dc=example,dc=com
    ldap_group_attribute=memberOf
    ldap_group_base=ou=groups,dc=example,dc=com
    # if anon leave the value on the right side of the equal line blank
    ldap_auth_dn=cn=authuser,ou=people,dc=example,dc=com
    # if anon leave the value on the right side of the equal line blank
    ldap_auth_dn_pw=mypass123
    ldap_account_prefix=cn
    ldap_group_prefix=cn
    ldap_valid_groups=["group1", "group2", "group3"]
    #leave laika_system as a user its a built in account for lookup up newness values from laikadq when running scans
    LAIKA_AUTH_VALID_USERS=["laika_system"]
    ```
1. Copy etc/dist/laika_cluster.conf /etc/laikaboss/laika_cluster.conf
1. Run the script python3 <laikaboss src repo>/setup-secrets.py
    In addition to ldap you can use the default username and password generated in this file /etc/laikaboss/secrets/local_creds
1. Build the latest docker container
   <source code repo>/env.sh
   <source code repo>/Docker/make-container3.sh
1. Build the latest apache container
   <source code repo>/env.sh
   <source code repo>/Docker/apache/make-container.sh
1. cd <source code repo>
1. docker compose up
1. Go to https://<yourhost>:443 and login with your ldap username and password (or the default password in /etc/laikaboss/secrets/local_creds)
    * you will have to accept the self-signed cert which was issued
1. Change the env.sh image name to something you want to use at your site
1. Rebuild the LB and apache containers
1. Push docker images to a central repository hosted at your site so you can pull them down to other cluster nodes by name.
1. Modify the docker-compose.xml file to use the new image tags.
###### Post Configuration
1. Get a real certificate for your system and install it in /etc/laikaboss/secrets/server.crt and /etc/laikaboss/secrets/server.key in pem format, and /etc/laikaboss/secrets/cacert.crt (you can append multiple files into the same ca file)
   apache, redis, and the email server (for starttls)  all use that certificate 
1. Make sure docker is running on start up
   sudo systemctl enable docker 
1. Test the email service against your box hosting laikamail service - using s-nail/mailx examples: https://www.systutorials.com/sending-email-using-mailx-in-linux-through-internal-smtp/
   echo "test message" | s-nail -s "test app" -S smtp="127.0.0.1:25" -S from="test@example.com" scan@localhost   #(or scan@<fqhostname> - what the recipients param is set to in the configs"
1. Install a log monitoring agent and monitor file 
   /var/log/laikaboss/laikaboss_splunk.log
1. Set up a local firewall blocking open ports from off of the system or cluster
   Required ports available outside the cluster are 443(https), and port 25(smtp with start-tls)
   You could make port 9002 available if you wish to make minio accessible directly
   Within the cluster port 9002(minio S3 and minio GUI), 443(https), 6379(redis over SSL)
1. On redundant servers you must copy the /etc/laikaboss folder including any relevant keys/password etc in /etc/laikaboss/secrets, create the local laikaboss account and run the setup-host.sh script to create the necessary directories and permissions.
1. Create at least 2 servers which handle mail for redundancy - these servers can be co-located with any of the other services
   - SMTP is the most important box for redundancy - because if SMTP is down, it will CAUSE email bounces.  
   The docker compose file for an email box only needs to contain the services laikamail and laikacollector
1. Optional:  Install multiple laikadq worker hosts - they only need to have the services laikadq and submitstoraged installed
1. Configure your primary email server to send BCC emails to scan@<your host> on your mail hosts
1. docker-compose up -d
#leave laika_system as a user its a built in account if you don't have ldap setup
LAIKA_AUTH_VALID_USERS=["laika_system"]

###### MAINTENANCE
1. A sample requirements3.txt has been included which pins modules to known working versions.  To update it - you'll need to mount the source code in a container and recreate it - with the latest versions. This command will 
   pip-compile --output-file=requirements3.txt requirements3.in
Rerun the tests
   docker-compose run  https://example.com:1234/laikaboss/laikaboss laikadq -t
