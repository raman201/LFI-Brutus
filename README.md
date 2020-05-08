# LFI Brutus
Use this utility when you find a point for LFI to automatically go through a number of common files.


Requires `requests` : `pip install requests`


## Usage

    usage: python lfi-brute.py [-h] [--nullbyte] [--ssl] [--dir-file DIR_FILE]
                        [--windows] [--debug] [-v] [-k] [-o OUTFILE]
                        [-s SURPRESS_OUTPUT]
                        host path

brute force common directories with a file-inclusion point

## Arguments

| Argument         |        Description | 
| ---------------- | ------------------ |
|  host | IP address to scan. Example: 127.0.0.1
|  path | Local file inclusion path. Example: /section.php?page=/../../../../..                     
|  -h, --help | show this help message and exit
|  --nullbyte | terminate the url with null byte
|  --ssl | Use SSL for connection (https)
|  --dir-file DIR_FILE  | Input file for directory sweep
|  --windows | Indicate windows target
|  --debug | Complete setup without running against host
|  -v, --verbose | Verbose output
|  -k, --verify-ssl | Verify SSL certificates
|  -o OUTFILE, --outfile OUTFILE | Write output to this file
|  -s,--surpress-output  | SURPRESS_OUTPUT Do not print results to screen

# LFI-Brutus
