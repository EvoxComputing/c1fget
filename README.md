# c1fget.sh
C1fApp script for retrieving lists with API


```
C1fapp threat list Bash script
Usage: c1fget.sh -k <c1fapp key> or -f <c1fapp key file> [options...]
Options:
  -k/--key <c1fapp key> Provide the C1fapp feed key. If no other argumnet Menu will prompt
  -f/--file   <file>    Set file containing the C1fapp feed key. If no other argumnet Menu will prompt
  -a/--all            	ALL feeds not JSON
  -b/--bro            	C1fapp Bro Ids combined
  -d/--dom            	Domain threat feed list
  -i/--infra           	Infrastructure threat feed list
  -j/--json            	Json threat feed list
  -u/--url            	URL threat feed list
  -h/--help             Output this message
  -V/--version          Output version number

If you don't have cURL installed, download it at http://curl.haxx.se/
```

Project summary at
http://evoxcomputing.github.io/c1fget
