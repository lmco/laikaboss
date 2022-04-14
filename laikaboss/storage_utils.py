# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S.
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from future import standard_library
standard_library.install_aliases()
from builtins import str
import logging
import socket
import io
from laikaboss.util import toBool
from collections import OrderedDict
from minio import Minio
from minio.error import InvalidResponseError, S3Error
import copy
import urllib.parse as up
from . import lbconfigparser

from collections import namedtuple
_dns_retries = 5
_sentinel_port=26379
_socket_keepalive = True
Minio_url_parts = namedtuple('Minio_url_parts', "netloc,access_key,secret_key,secure,bucket_prefix")
Redis_url_parts = namedtuple('Redis_url_parts', "scheme,hostname,path,port,query,username,password,params,fragment,kwargs")

def _put_file_minio_bucket(minio_client, bucket, minio_filename, buf):
    """ Attempts to place a file into a Minio bucket.
    Args:
        minio_client (Minio): The minio handler object
        bucket (str): The name of the bucket in which to place the file
        minio_filename (str): The path of the file relative to minio bucket
        buf: The file buffer

    Raises: 
        InvalidResponseError or S3Error:  If the file could not be placed in the bucket
    """
    iobuf = io.BytesIO(buf)
    # Attempt to submit file
    minio_client.put_object(bucket, minio_filename, iobuf, len(buf))
    iobuf.close()


def write_to_minio(minio_client, minio_client_url, bucket, minio_filename, buf):
    """ Write a given file buffer to minio

    Args:
        minio_client (Minio): The handler for minio requests
        minio_client_url (str): The host that is running minio
        bucket (str): The name of the bucket in which to add the file
        minio_filename (str): The path of the file relative to the minio bucket
        buf: The file buffer

    Returns:
        Response (list): 
            Item 0: The message indicating what happened
            Item 1: A status code indicating success or failure

    """

    logging.debug(
        "write_to_minio minio client:%s bucket:%s filename:%s len:%d"
        % (str(minio_client), bucket, minio_filename, len(buf))
    )

    bucket_prefix = minio_client.lb_get_bucket_prefix()

    if bucket_prefix:
       bucket = bucket_prefix + bucket

    try:
        try:
            # try to grab just part of the file (faster than grabbing the whole file) to check if it exists
            tmp = minio_client.get_object(bucket, minio_filename, offset=0, length=1)

        except S3Error as e:
            if e.code == "NoSuchBucket":
               logging.debug("Bucket [%s] does not exist! Creating the bucket", bucket)
               minio_client.make_bucket(bucket)
               # Add the file to the newly created bucket
               _put_file_minio_bucket(minio_client, bucket, minio_filename, buf)
            elif e.code == "NoSuchKey":
               # The file does not exist in the bucket, add it to the bucket
               _put_file_minio_bucket(minio_client, bucket, minio_filename, buf)
        else:
            # file was already in minio. Don't add the file again
            return "File already in minio\n\n", 409
    except InvalidResponseError as e:
        logging.exception(
            "There was a problem writing the filename: [%s] to the bucket: [%s]: [%s]"
            % (minio_filename, bucket, e)
        )
        return "There was a problem writing to the bucket. Try Again\n\n", 500

    return "Successfully added the file to minio\n\n", 200


def _get_senders(sender_list, access_key, secret_key):
    """ opens up and caches connections to all possible backend servers 

    Args:
        sender_list, list(str):  A list of server urls in the format host:port, if there is a failover server,
            an entry in the list can contain a semi colon delimited str of the format host1:port;host2:port, etc. 
        access_key (str): The minio access key (assumes the same key for all storage servers)
        secret_key (str): The minio secret key (assumes the same key for all storage servers)
        secure (bool): Whether or not the minio connection is encrypted (assumes the same status for all servers).

    returns:  
        an OrderedDict keyed by the first hostname for a failoverlist, each entry contains tuples of independent storage servers 
        and there failovers as parallel lists of hostnames, and their connection handles
        [([storagehost1:port(str), storagehost1-failover1:port(str)], [minio storagehost1_handle, minio_storagehost-failover1_handle]),
            ([storagehost2:port(str), storagehost2-failover1:port(str)], [minio storagehost2_handle, minio_storagehost-failover2_handle])]

        Here is a sample construct that this generates:
        {
            "172.17.1.1:9000;10.1.1.1:9000|172.18.1.1:9000": { <-- The key here is the original input of 'storage_url'
                "172.17.1.1:9000": [
                    [
                        "172.17.1.1:9000",
                        "10.1.1.1:9000"
                    ],
                    [
                        "Minio handler for 172.17.1.1:9000",
                        "Minio handler for 10.1.1.1:9000"
                    ]
                ],
                "172.18.1.1:9000": [
                    [
                        "172.18.1.1:9000"
                    ],
                    [
                        "Minio handler for 172.18.1.1:9000"
                    ]
                ]
            }
        }
    """
    result = OrderedDict()
    for sender in sender_list:
        val = []
        val_str = []
        if ";" in sender:
            failover_list = sender.split(";")
            failover_list = [failover.strip() for failover in failover_list]
        else:
            failover_list = [sender]

        for url_str in failover_list:
            minio = minioclient_from_url(url_str, access_key, secret_key)
            logging.info("Minio storage - Adding url %s " % (str(url_str)))
            val.append(minio)
            val_str.append(url_str)
        result[val_str[0]] = (val_str, val)
    return result

class LBMinio(Minio):
    def __init__(self, netloc, access_key=None, secret_key=None, secure=None, bucket_prefix=None, **kwargs):

       self._lb_netloc = netloc
       self._lb_access_key = access_key
       self._lb_bucket_prefix = bucket_prefix

       super(LBMinio, self).__init__(netloc, access_key=access_key, secret_key=secret_key, secure=secure, **kwargs)

    def lb_get_bucket_prefix(self):
        return self._lb_bucket_prefix

    def lb_get_access_key(self):
        return self._lb_access_key

    def lb_get_netloc(self):
        return self._lb_netloc

    def __str__(self):
        ret = 'LBMinio(netloc='+self._lb_netloc+', access_key[:4]=' + self._lb_access_key[:4] + ', bucket_prefix='+str(self._lb_bucket_prefix)+ ')'
        return ret


def generate_minio_handlers(urls_str, senders_dict, access_key = None, secret_key = None):
    """ Creates a dictionary construct that generates all the Minio
        handlers for a particular value in storage url.
    
    Args:
        urls_str (str): A url or url list in the following format:
            URL1:PORT[[;FAIL_OVER_URLS][|URL2:PORT[;FAIL_OVER_URLS]]]...
            For example these are all valid values:
                - 172.17.1.1:9000;10.1.1.1:9000|172.18.1.1:9000
                - 192.168.1.1:9000|172.10.1.2:8000
                - domain.sample.com:8888|172.1.1.1:9999
                - 172.17.1.1:80
        senders_dict (OrderedDict): A cache of previous return values to this function
            to avoid recomputing the construct of Minio handlers
        access_key (str): The minio access key (assumes the same key for all storage servers)
        secret_key (str): The minio access key (assumes the same key for all storage servers)

        it assumes all urls are over ssl unless http:// is specified as the scheme
    
    Returns:
        A list of 2 items:
            Item1: senders_dict
            Item2: The specific value for key urls_str in senders_dict

    """
    if urls_str and urls_str not in senders_dict:
        url_with_failover = urls_str.split('|')
        url_with_failover = [url.strip() for url in url_with_failover]
        # this is a caching mechanism for the object, so it doesn't
        # reopen the handles with every run
        senders_dict[urls_str] = _get_senders(url_with_failover, access_key, secret_key)

    return senders_dict, senders_dict[urls_str]

def minioclient_from_url(urlstr, default_access=None, default_secret=None, **kwargs):

    minio_url_parts = minioclient_from_url_parts(urlstr, default_access, default_secret, **kwargs)

    return LBMinio(**(minio_url_parts._asdict()))


def minioclient_from_url_parts(urlstr, default_access=None, default_secret=None, **kwargs):

    # change the default for 
    if 'dns_check' not in kwargs:
       kwargs['dns_check'] = False

    bucket_prefix = None

    (scheme, hostname, path, port, query, username, password, params, fragment) = urlparse(urlstr, default_scheme = 's3', default_port=443, **kwargs)

    secure = True

    if scheme and scheme.lower()  == "http":
       secure = False

    access = default_access
    secret = default_secret

    if username:
      access = username

    if password:
       secret = password

    netloc = build_netloc(hostname, port=port)

    if query:
       query_items = up.parse_qs(query)
       if 'bucket_prefix' in query_items:
          bucket_prefix = query_items['bucket_prefix'][0]

    return Minio_url_parts(netloc=netloc, access_key=access, secret_key=secret, secure=secure, bucket_prefix=bucket_prefix)

def sentinel_parse_and_verify_netlocs(netlocs):

    from redis.sentinel import Sentinel

    if not isinstance(netlocs, list):
        netlocs = [netlocs]

    result = []
    for netloc in netlocs:
        ips = None
        host = netloc
        port = _sentinel_port
        if ':' in netloc:
            host, port = netloc.split(':')
            port = int(port)
        try:
           ips = socket.getaddrinfo(host, 80, 0, 0, socket.IPPROTO_TCP)
        except socket.gaierror as e:
           continue

        if ips:
           result.append((host, port))

    return result

def redisclient_from_url(urlstr, db=None, **kwargs):

    from redis.sentinel import Sentinel
    import redis

    parts = redisclient_url_parts(urlstr, db=db, **kwargs)

    kwargs = copy.deepcopy(parts.kwargs)

    if parts.scheme in ["sentinel", "sentinels"]:

      query_dict = {}

      if parts.query:
          query_dict = up.parse_qs(parts.query)

          # merge but flatten lists into single items
          for key, value in query_dict.items():
              if len(value) == 1:
                 kwargs[key] = value[0]
              else:
                 kwargs[key] = value

      if not 'ssl' in kwargs:
          kwargs["ssl"] = True if parts.scheme == 'sentinels' else False

      if parts.password:
          kwargs['password'] =  parts.password

      if parts.username:
          kwargs['username'] =  parts.username

      master_set = 'mymaster'

      sentinel_netlocs = [(parts.hostname + ':' + str(parts.port))]

      master_set = kwargs.get('sentinel_master_set', master_set)

      kwargs.pop('sentinel_master_set', None)

      if 'sentinel' in kwargs:
          sentinel_netlocs.extend(query_dict['sentinel'])
          kwargs.pop('sentinel', None)

      if 'socket_keepalive' not in kwargs:
         kwargs['socket_keepalive'] = _socket_keepalive

      sentinel_kwargs = copy.deepcopy(kwargs)

      sentinel_netloc_tuples = sentinel_parse_and_verify_netlocs(sentinel_netlocs)

      sentinel = Sentinel(sentinel_netloc_tuples, sentinel_kwargs = sentinel_kwargs, **kwargs)

      return sentinel.master_for(master_set, socket_keepalive = _socket_keepalive)

    else:
       urlstr = urlunparse(**(parts._asdict()))

       # we can't have this as 2 different arguments
       if 'db' in kwargs:
           db = kwargs['db']
           del kwargs['db']

       return redis.from_url(urlstr, db=db, **kwargs)

def redisclient_url_parts(urlstr, db=None, **kwargs):

    from urllib.parse import parse_qs, urlencode

    (scheme, hostname, path, port, query, username, password, params, fragment) = urlparse(urlstr, default_scheme = 'redis', default_port=6379, **kwargs)

    kwargs  = copy.deepcopy(kwargs)

    if query:

        query_dict = parse_qs(query)

        if path:
           db = path.lstrip('/')
           if db:
              kwargs['db'] = db

        # do seq will encode arrays as multiple k1=blah,k1=bhal2, rather than keeping them as strinified arrays kie k1=[blah,blah2]
        query = str(urlencode(query_dict, doseq=True))

    redis_url_parts = Redis_url_parts(scheme, hostname, path, port, query, username, password, params, fragment, kwargs)

    return redis_url_parts

def urlparse(urlstr, default_port=None, default_scheme=None, **kwargs):

    urlstr_orig = urlstr

    if urlstr and '/' not in urlstr:
       urlstr = default_scheme + "://" + urlstr

    p1 = urlstr.find('//')
    p2 = urlstr.find('@')

    # fix an error in urlparsing that
    # that forward slashes can't be included
    # in the password
    if p1 > 0 and p2 > 0:

        mid = urlstr[p1+2: p2]
        mid = mid.replace('/', "%2F")
        pre  = urlstr[:p1+2]
        post = urlstr[p2:]
        urlstr = pre + mid + post

    url = up.urlparse(urlstr)

    if not url.netloc:
        raise ValueError("hostname blank or unreadable url:" + str(urlstr_orig) + ' for host')

    port = url.port

    if not port and default_port:
        port = int(default_port)

    hostname = url.hostname
    username = url.username
    password = url.password

    # get the password from the supplied file
    if username and password:
       if username == "prefix":
              password = up.unquote(password)
              with open(password + '.access', "r") as f:
                 username = f.read().strip()
              with open(password + '.secret', "r") as f:
                 password = f.read().strip()
       elif username == "file":
          with open(up.unquote(password), "r") as f:
             username = ''
             password = f.read().strip()
             if ':' in password:
                 (username, password) = password.split(':')

    # this is needed since the redis libs were hitting the dns servers thousands of times a second
    # if the hostname doesn't exist in the redis url.
    if toBool(kwargs.get('dns_check',True), True):
       ips = None
       for x in range(_dns_retries):
          try:
             ips = socket.getaddrinfo(hostname, 80, 0, 0, socket.IPPROTO_TCP)
             break
          except socket.gaierror as e:
             time.sleep(3)

       if not ips:
           raise ValueError("dns lookup failed on hostname:" + str(hostname) + ' for redis url:' + str(urlstr_orig) + ' possibly from sentinel')

    if username:
       username = up.unquote(username)

    if password:
       password = up.unquote(password)

    return (url.scheme, hostname, url.path, port, url.query, username, password, url.params, url.fragment)

def build_netloc(hostname, port=None, username=None, password=None):

    netloc = ""

    if username:
       username = up.quote(username)

    if password:
       password = up.quote(password)

    if username or password:
       netloc = str(username) + ':' + str(password) + '@'

    netloc += hostname

    if port:
       netloc += (':' + str(port))

    return netloc

def urlunparse(scheme, hostname, path='', port='', query='', username='', password='', params='', fragment='', **kwargs):

    netloc = build_netloc(hostname, port, username, password)

    url = up.urlunparse((str(scheme), str(netloc), str(path), str(params), str(query), str(fragment)))

    return url


