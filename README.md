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


+ **laikad**

	This piece contains the code for running Laika as a deamonized, networked service using the ZeroMQ broker.


+ **cloudscan**

	A command-line client for sending a local system file to a running service instance of Laika (laikad).


+ **modules**

	The scan itself is composed of the running of modules. Each module is its own program that focuses on a particular sub-component of the overall file analysis.


## Getting Started
Laika BOSS has been tested on the latest versions of CentOS and Ubuntu LTS

##### Installing on Ubuntu
+ Install framework dependencies:
```shell
apt-get install yara python-yara python-progressbar
pip install interruptingcow
```
+ Install network client and server dependencies:
```shell
apt-get install libzmq3 python-zmq python-gevent python-pexpect
```
+ Install module dependencies:
```shell
apt-get install python-ipy python-m2crypto python-pyclamd liblzma5 libimage-exiftool-perl python-msgpack libfuzzy-dev python-cffi python-dev unrar
pip install fluent-logger olefile ssdeep py-unrar2 pylzma oletools
wget https://github.com/smarnach/pyexiftool/archive/master.zip
unzip master.zip
cd pyexiftool-master
python setup.py build
python setup.py install
wget http://pefile.googlecode.com/files/pefile-1.2.10-139.tar.gz
tar vxzf pefile-1.2.10-139.tar.gz
cd pefile-1.2.10-139
python setup.py build
python setup.py install
```
#### Installing Laika BOSS (optional)
You may use the provided setup script to install the Laika BOSS framework, client library, modules and associated scripts (laika.py, laikad.py, cloudscan.py).

```shell
python setup.py install
```

#### Standalone instance
From the directory containing the framework code, you may run the standalone scanner, laika.py against any file you choose. If you move this file from this directory you'll have to specify various config locations. By default it uses the configurations in the ./etc directory.

We recommend using installing [jq](http://stedolan.github.io/jq/) to parse Laika output.

```javascript
$ ./laika.py ~/test_files/testfile.cws.swf | jq '.scan_result[] | { "file type" : .fileType, "flags" : .flags, "md5" : .objectHash }'
100%[############################################] Processed: 1/1 total files (Elapsed Time: 0:00:00) Time: 0:00:00
{
  "md5": "dffcc2464911077d8ecd352f3d611ecc",
  "flags": [],
  "file type": [
    "cws",
    "swf"
  ]
}
{
  "md5": "587c8ac651011bc23ecefecd4c253cd4",
  "flags": [],
  "file type": [
    "fws",
    "swf"
  ]
}
```

#### Networked instance
```javascript
$ ./laikad.py

$ ./cloudscan.py ~/test_files/testfile.cws.swf | jq '.scan_result[] | { "file type" : .fileType, "flags" : .flags, "md5" : .objectHash }'
{
  "md5": "dffcc2464911077d8ecd352f3d611ecc",
  "flags": [],
  "file type": [
    "cws",
    "swf"
  ]
}
{
  "md5": "587c8ac651011bc23ecefecd4c253cd4",
  "flags": [],
  "file type": [
    "fws",
    "swf"
  ]
}
```

#### Milter
The Laika BOSS milter server allows you to integrate Laika BOSS with mail transfer agents such as Sendmail or Postfix. This enables better visibility (passive visibility can be hampered by TLS) and provides a means to block email according to Laika BOSS disposition.

```
+----------------+             +---------------+             +----------------+
|                |    email    |               |   email     |                |
|    sendmail    +------------->  laikamilter  +------------->     laikad     |
|                | accept/deny |               | scan result |                |
|                <-------------+               <-------------+                |
+----------------+             +---------------+             +----------------+
```

The Laika BOSS milter server requires the [python-milter](https://pythonhosted.org/milter) module and the Laika BOSS client library. Check out the comments in the source code for more details.

##### Licensing
The Laika framework and associated modules are released under the terms of the Apache 2.0 license.
