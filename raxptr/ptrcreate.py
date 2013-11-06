#!/usr/bin/env python
# =============================================================================
# Copyright [2013] [Kevin Carter]
# License Information :
# This software has no warranty, it is provided 'as is'. It is your
# responsibility to validate the behavior of the routines and its accuracy
# using the code provided. Consult the GNU General Public license for further
# details (see GNU General Public License).
# http://www.gnu.org/licenses/gpl.html
# =============================================================================

try:
    import argparse
except ImportError:
    print('You need to have argparse installed. Please install it.')
import httplib
import json
import os
import sys
import time
import traceback
import urlparse


# All available RAX regions.
__rax_regions__ = ['dfw', 'ord', 'iad', 'lon', 'syd', 'hkg']
__version__ = 2.0



def get_help():
    """Get Argument help.

    :returns parser.print_help(): returns help information.
    """

    parser = arguments()
    return parser.print_help()


def get_args():
    """Parse all arguments to run the application.

    :returns vars(parser.parse_args()): args as a dictionary
    """

    parser = arguments()
    args = dict_pop_none(
        dictionary=vars(
            parser.parse_args()
        )
    )
    confirm_args(args=args)
    return args


def arguments():
    """Parse the Command Line Arguments."""

    par = argparse.ArgumentParser(
        usage='%(prog)s',
        description=(
            '%(prog)s create a PTR record for your Rackspace Cloud Server.'
        ),
        epilog='GPLv3 Licensed PTR Create Version %s.' % __version__
    )

    par.add_argument('-D',
                     '--domain-name',
                     metavar='',
                     help='Domain Name for the PTR Record',
                     required=True,
                     default=None)
    par.add_argument('--ttl',
                     metavar='',
                     help='TTL of DNS Record',
                     type=int,
                     default=56000)

    ids = par.add_mutually_exclusive_group(required=True)
    ids.add_argument('-N',
                     '--server-name',
                     metavar='',
                     help='The name of your server',
                     default=None)
    ids.add_argument('-I',
                     '--server-id',
                     metavar='',
                     help='The ID of your server',
                     default=None)

    par.add_argument('-U',
                     '--user',
                     metavar='',
                     help='Your Rackspace Username',
                     default=os.getenv('OS_USERNAME'))

    key = par.add_mutually_exclusive_group()
    key.add_argument('-P',
                     '--password',
                     metavar='',
                     help='Your Rackspace Password',
                     default=os.getenv('OS_PASSWORD'))
    key.add_argument('-A',
                     '--apikey',
                     metavar='',
                     help='Your Rackspace API Key',
                     default=os.getenv('OS_APIKEY'))
    key.add_argument('-T',
                     '--token',
                     metavar='',
                     help='Your Rackspace Token',
                     default=os.getenv('OS_TOKEN'))

    par.add_argument('-R',
                     '--region',
                     metavar='',
                     choices=__rax_regions__,
                     help='Regions: %s' % __rax_regions__,
                     default=os.getenv('OS_REGION'))
    par.add_argument('--auth-url',
                     metavar='',
                     help='Optional Override for the Authentication URL',
                     default=os.getenv('OS_AUTH_URL'))
    par.add_argument('--auth-version',
                     metavar='',
                     help='Optional Rackspace Authentication Version',
                     default=os.getenv('OS_AUTH_VERSION', 'v2.0'))
    par.add_argument('--debug',
                     action='store_true',
                     help='Enable Debug Mode',
                     default=False)
    par.add_argument('--no-confirm',
                     action='store_true',
                     help='Skip Record Confirmation.',
                     default=False)
    par.add_argument('-V',
                     '--version',
                     action='version',
                     version='PTRCreate %s' % __version__)
    return par


def confirm_args(args):
    if 'user' not in args:
        raise SystemExit('No Username Specified.')
    if not any(['password' in args, 'apikey' in args, 'token' in args]):
        raise SystemExit('No Password, APIKEY, or Token Specified.')
    if 'region' not in args:
        raise SystemExit('No Region Specified.')


def dict_pop_none(dictionary):
    """Parse all keys in a dictionary for Values that are None.

    :param dictionary: all parsed arguments
    :returns dict: all arguments which are not None.
    """

    return dict([(key, value) for key, value in dictionary.iteritems()
                 if value is not None if value is not False])


def authenticate(args):
    """Authentication For Openstack API.

    Pulls the full Openstack Service Catalog Credentials are the Users API
    Username and Key/Password "osauth" has a Built in Rackspace Method for
    Authentication

    Set a DC Endpoint and Authentication URL for the OpenStack environment

    :param auth_dict: required parameters are auth_url
    """

    # Setup the request variables
    url = parse_region(args)
    a_url = parse_url(url=url, auth=True)
    auth_json = parse_reqtype(args)

    # remove the prefix for the Authentication URL if Found
    auth_json_req = json.dumps(auth_json)
    headers = {'Content-Type': 'application/json'}

    # Send Request
    request = ('POST', a_url.path, auth_json_req, headers)
    resp_read = request_process(aurl=a_url, req=request, args=args)
    try:
        auth_resp = json.loads(resp_read)
    except ValueError as exp:
        raise SystemExit('JSON Decode Failure. ERROR: %s - RESP %s'
                         % (exp, resp_read))
    else:
        auth_info = parse_auth_response(auth_resp, args)
        token, tenant, user, inet, enet = auth_info
        return token, tenant, user, inet, enet


def parse_url(url, auth=False):
    """Return a clean URL. Remove the prefix for the Auth URL if Found.

    :param url:
    :return aurl:
    """

    def is_https(iurl):
        """Check URL to determine the Connection type.

        :param iurl:
        :return 'complete url string.':
        """

        if 'rackspace' in iurl:
            return 'https://%s' % iurl
        else:
            return 'http://%s' % iurl

    if auth is True:
        if 'tokens' not in url:
            url = urlparse.urljoin(url, 'tokens')

    if url.startswith(('http', 'https', '//')):
        if url.startswith('//'):
            return urlparse.urlparse(url, scheme='http')
        else:
            return urlparse.urlparse(url)
    else:
        return urlparse.urlparse(is_https(iurl=url))


def parse_reqtype(args):
    """Setup our Authentication POST.

    username and setup are only used in APIKEY/PASSWORD Authentication
    """

    setup = {'username': args.get('user')}
    if args.get('token') is not None:
        auth_body = {'auth': {'token': {'id': args.get('token')},
                              'tenantName': args.get('tenant')}}
    elif args.get('apikey') is not None:
        prefix = 'RAX-KSKEY:apiKeyCredentials'
        setup['apiKey'] = args.get('apikey')
        auth_body = {'auth': {prefix: setup}}
    elif args.get('password') is not None:
        prefix = 'passwordCredentials'
        setup['password'] = args.get('password')
        auth_body = {'auth': {prefix: setup}}
    else:
        raise AttributeError('No Password, APIKey, or Token Specified')
    return auth_body


def get_surl(tenant_id, endpoint_list, lookup, region=None):
    """Lookup a service URL.

    :param region:
    :param cf_list:
    :param lookup:
    :return net:
    """

    for srv in endpoint_list:
        if region is not None:
            if region in srv.get('region'):
                net = parse_url(url=srv.get(lookup))
                return net
        elif tenant_id in srv.get('tenantId'):
            net = parse_url(url=srv.get(lookup))
            return net
    else:
        raise SystemExit('Nothing found in your Service Catalog.')


def parse_auth_response(auth_response, args):
    """Parse the auth response and return the tenant, token, and username.

    :param auth_response: the full object returned from an auth call
    :returns: tuple (token, tenant, username, internalurl, externalurl, cdnurl)
    """

    access = auth_response.get('access')
    token = access.get('token').get('id')

    if 'tenant' in access.get('token'):
        tenant = access.get('token').get('tenant').get('name')
        user = access.get('user').get('name')
    elif 'user' in access:
        tenant = None
        user = access.get('user').get('name')
    else:
        raise SystemExit('No Token Found to Parse.\nHere is the DATA: %s\n%s'
                         % (auth_response, traceback.format_exc()))

    scat = access.pop('serviceCatalog')
    dnss = None
    servers = None
    for srv in scat:
        if srv.get('name') == 'cloudDNS':
            dnss = srv.get('endpoints')
        if srv.get('name') == 'cloudServersOpenStack':
            servers = srv.get('endpoints')

    if args.get('region') is not None:
        region = args.get('region', 'no_region')
        region = region.upper()
    else:
        raise SystemExit('No Region Set')

    servernet = get_surl(
        tenant_id=tenant,
        endpoint_list=servers,
        lookup='publicURL',
        region=region
    )
    dnsnet = get_surl(
        tenant_id=tenant,
        endpoint_list=dnss,
        lookup='publicURL'
    )

    return token, tenant, user, dnsnet, servernet


def parse_region(args):
    """Pull region/auth url information from context."""

    base_auth_url = (
        'identity.api.rackspacecloud.com/%s/tokens' % args.get('auth_version')
    )

    if args.get('region'):
        region = args.get('region')
    else:
        raise SystemExit('You Are required to specify a REGION')

    if region.lower() is 'lon':
        return 'lon.%s' % base_auth_url
    elif region.lower() in __rax_regions__:
        return '%s' % base_auth_url
    else:
        if args.get('auth_url'):
            if 'racksapce' in args.get('auth_url'):
                return args.get('auth_url', '%s' % base_auth_url)
            else:
                return args.get('auth_url')
        else:
            raise SystemExit('You Are required to specify a'
                             ' REGION and an AUTHURL')


def request_process(aurl, req, args):
    """Perform HTTP(s) request based on Provided Params.

    :param aurl:
    :param req:
    :param https:
    :return read_resp:
    """

    conn = open_connection(url=aurl, args=args)

    # Make the request for authentication
    try:
        _method, _url, _body, _headers = req
        conn.request(method=_method, url=_url, body=_body, headers=_headers)
        resp = conn.getresponse()
    except Exception as exc:
        raise AttributeError("Failure to perform Authentication %s ERROR:\n%s"
                             % (exc, traceback.format_exc()))
    else:
        resp_read = resp.read()
        status_code = resp.status
        if status_code >= 300:
            raise httplib.HTTPException('Failed to authenticate %s'
                                        % status_code)
        return resp_read


def open_connection(url, args):
    """Open an Http Connection and return the connection object.

    :param url:
    :return conn:
    """

    try:
        if url.scheme == 'https':
            conn = httplib.HTTPSConnection(url.netloc)
        else:
            conn = httplib.HTTPConnection(url.netloc)
    except httplib.InvalidURL as exc:
        msg = 'ERROR: Making connection to %s\nREASON:\t %s' % (url, exc)
        raise httplib.CannotSendRequest(msg)
    else:
        if args.get('debug') is True:
            conn.set_debuglevel(1)
        return conn


def request(conn, rpath, method='GET', body=None, headers=None):
    """Open a Connection."""

    if headers is None:
        headers = {}

    try:
        conn.request(method, rpath, body=body, headers=headers)
    except Exception:
        print('Connection issues, %s ' % traceback.format_exc())
    else:
        resp = conn.getresponse()
        return resp, resp.read()
    finally:
        conn.close()


def prep_payload(auth):
    """Create payload dictionary.

    :param auth:
    :return (dict, dict): payload and headers
    """

    # Unpack the values from Authentication
    token, tenant, user, dnsnet, serversnet = auth
    md = {}

    # Get the headers ready
    headers = {'X-Auth-Token': token, 'Content-type': 'application/json'}

    # Set the upload Payload
    md['tenant'] = tenant
    md['headers'] = headers
    md['user'] = user
    md['dns'] = dnsnet
    md['servers'] = serversnet
    return md


def get_servers(payload, args, server_id=None):
    """Get all servers in a Region."""

    def _request():
        """Make a request."""

        resp, read = request(
            conn=conn,
            rpath=path,
            method='GET',
            headers=payload['headers']
        )

        if resp.status >= 300:
            raise SystemExit('Error in processing: %s' % resp.msg)
        else:
            return json.loads(read)

    conn = open_connection(url=payload['servers'], args=args)
    if server_id is None:
        path = '%s/servers' % payload['servers'].path
        return _request().get('servers')
    else:
        path = '%s/servers/%s' % (payload['servers'].path, server_id)
        return _request()


def get_servers_id(servers, args):
    """Get an Instance ID."""

    sid = args.get('server_name', args.get('server_id'))
    for server in servers:
        if server.get('name') == sid:
            return server.get('id')
        elif server.get('id') == sid:
            return server.get('id')
    else:
        raise SystemExit('No Server Found.')


def get_ips(server):
    """Parse a list Addresses for a server and return it."""

    _server = server.get('server')
    _addresss = _server.get('addresses')
    publics = _addresss.get('public')
    return [public.get('addr') for public in publics]


def setup_ptr(ips, args, payload, server_id):
    """Create a PTR Record POST."""

    def _record(ip_addr):
        """Build individual records."""

        return {
            "name": args['domain_name'],
            "type": "PTR",
            "data": ip_addr,
            "ttl": args['ttl']
        }

    records = [_record(ip) for ip in ips]
    server_path = '%s/servers/%s' % (
        urlparse.urlunparse(payload['servers']), server_id
    )

    ptr_record = {
        "recordsList": {
            "records": records
        },
        "link": {
            "content": "",
            "href": server_path,
            "rel": "cloudServersOpenstack"
        }
    }
    if args.get('no_confirm') is not True:
        print('Please verify The new Proposed PTR record(s)')
        print(json.dumps(ptr_record, indent=2))
    return ptr_record


def delete_old_ptr(args, payload, server_id):
    """Delete the old PTR Record found on the Instance."""

    def _request(path):
        """Make a request."""

        resp, read = request(
            conn=conn,
            rpath=path,
            method='DELETE',
            headers=payload['headers']
        )

        if resp.status >= 300:
            raise SystemExit('Error in processing: %s' % resp.msg)

    print('Performing PTR record DELETE for old Records on Instance %s.'
          % server_id)
    server_path = '%s/servers/%s' % (
        urlparse.urlunparse(payload['servers']), server_id
    )

    conn = open_connection(payload['dns'], args=args)
    dns_path = payload['dns'].path
    delete_path = (
        '%s/rdns/cloudServersOpenstack?href=%s' % (dns_path, server_path)
    )
    _request(path=delete_path)


def post_new_ptr(args, payload, ptr_record):

    def _request(path):
        """Make a request."""

        resp, read = request(
            conn=conn,
            rpath=path,
            method='POST',
            body=json.dumps(ptr_record),
            headers=payload['headers']
        )

        if resp.status >= 300:
            raise SystemExit('Error in processing: %s' % resp.msg)
        else:
            return json.loads(read)

    conn = open_connection(payload['dns'], args=args)
    dns_path = payload['dns'].path
    post_path = (
        '%s/rdns/' % dns_path
    )
    post_request = _request(path=post_path)
    if 'request' in post_request:
        post_request['request'] = json.loads(post_request['request'])
    print('Please verify your new PTR record(s)')
    print(json.dumps(post_request, indent=2))


def confirm_create(args):
    # raw_input returns the empty string for "enter"

    if args.get('no_confirm') is True:
        return True
    else:
        print('Enter "yes" to continue or "no" to quit')
        choice = raw_input().lower()
        if choice in ('yes', 'y', 'ye', ''):
            return True
        elif choice in ('no', 'n'):
            return False
        else:
            raise SystemExit('Please respond with "yes" or "no"')


def executable():
    """Execute the application."""

    if len(sys.argv) <= 1:
        get_help()
        raise SystemExit('No Arguments Given.')
    else:
        args = get_args()

    post_auth = authenticate(args)
    payload = prep_payload(post_auth)
    sid = get_servers_id(get_servers(payload=payload, args=args), args)
    server_detail = get_servers(payload=payload, server_id=sid, args=args)
    server_ips = get_ips(server=server_detail)

    ptr = setup_ptr(server_ips, args, payload, sid)

    if confirm_create(args) is False:
        raise SystemExit('Nothing Done.')

    delete_old_ptr(args, payload, sid)
    print('Waiting a second before Posting new records.')
    time.sleep(5)
    post_new_ptr(args, payload, ptr)

if __name__ == "__main__":
    executable()
