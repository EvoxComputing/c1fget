#!/bin/bash
#author:verestio
#taken from internet can't remember where
#set -u
# ^ unbound (i.e. unassigned) variables shall be errors.
set -e
# ^ error checking :: Highly Recommended (caveat:  you can't check $? later).  

#C1fapp Threat Feeds
c1fapp_feeds="c1fapp_bro infra domain url json malware ALL"
c1fapp_feeds_json=(infra url domain)


#C1fapp Threat Feed lists 
c1fapp_lists_c1fapp_bro=(malware)
c1fapp_lists_domain=(botnet botnet_full malware malware_full whitelist)
c1fapp_lists_infra=(botnet botnet_full malware malware_full scan suspicious suspicious_full whitelist)
c1fapp_lists_url=(botnet malware)
c1fapp_lists_malware=(md5)

#Json Thread Feed lists
c1fapp_lists_json_domain=(botnet_full malware_full whitelist_full phishing_full)
c1fapp_lists_json_infra=(botnet_full malware_full whitelist_full suspicious_full)
c1fapp_lists_json_url=(botnet_full malware_full)
 
########################################

#c1fapp variables
c1fapp_uri="/cifapp/apilistget"
args=("$@")

#Linux commands
CWD="$(pwd)"
open_file="$(whereis cut | cut -d: -d' '  -f2)"
list_zip="$(whereis  gzip | cut -d: -d' '  -f2)"

#check if executableis exist
if [ ! -x "$open_file" ] ; then 
 	echo "$open_file doesn_t exist install it please" 
	exit 0
fi

if [ ! -x "$list_zip" ]; then 
 	echo "$list_zip doesn_t exist install it please" 
	exit 0
fi

timeout=3

#Proxy Settings 

#www.c1fapp.com Bash script Version #
#date = 01/05/2015
version="0.1.1"

function decoration ()
 {

	for decor in $(seq 1 80)
	do
		echo -n "*"
	done
		echo  ""
}

function c1fapp_dir {

	if [ -d "${CWD}/c1fapp_Threat_Feed" ]; then
		decoration
		echo "Directory c1fapp_Threat_Feed allready exists!"
		    decoration
		feed_dir="${CWD}/c1fapp_Threat_Feed"
	else
		mkdir -p "${CWD}/c1fapp_Threat_Feed"
		feed_dir="${CWD}/c1fapp_Threat_Feed"
		decoration
		echo "Creating Directory ${CWD}/c1fapp_Threat_Feed to keep your lists"
		decoration
    fi

}

function check_AAA () {

http_status="$(curl -Is  -w %{http_code} "https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/infra_malware/csv/" --output '/dev/null')"


	if [ $http_status -eq 403 ];then
        	decoration
		echo "The key you are using has expired. \n Please contact Evox Computing Ltd. for assiatnce or renew your key"
        	decoration
	    	exit 1
	else
		echo "The key you are using is valid"
		decoration

		fi

}

function OutputUsage
{
  echo "C1fapp threat list Bash script"
  echo "Usage: `basename $0` -k <c1fapp key> or -f <c1fapp key file> [options...]"
  echo "Options:"
  echo "  -k/--key <c1fapp key> Provide the C1fapp feed key. If no other agumnet Menu will prompt"
  echo "  -f/--file   <file>    Set file containing the C1fapp feed key. If no other agumnet Menu will prompt"
  echo "  -a/--all           	ALL feeds INCLUDING JSON"
  echo "  -b/--bro            	C1fapp Bro Ids combined"
  echo "  -d/--dom            	Domain Malware / Botnet / Whitelist threat feed list"
  echo "  -i/--infra           	Infrastructure Malware / Botnet / Scan / Suspicious / Whitelist threat feed list"
  echo "  -j/--json            	Json format Domain / Infrastructure / URL threat feed list"
  echo "  -u/--url            	URL Botnet / Malware threat feed list"
  echo "  -h/--help             Output this message"
  echo "  -V/--version          Output version number" 
  echo
  echo "If you don't have cURL installed, download it at http://curl.haxx.se/"

  exit 1
}


function bro_feeds () {
		
		for list in "${c1fapp_lists_c1fapp_bro[@]}"
                do

                           c1fapp_feed="https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/c1fapp_${list}/bro/"
                           out_file="c1fapp_${list}.bro.gz"
                           echo "------Downloading ${out_file}------------"  
                           #echo "$(wget -r -N $c1fapp_feed $feed_dir/$out_file)"
                           echo "$(curl -R -f $c1fapp_feed --connect-timeout $timeout --keepalive --output $feed_dir/$out_file)"
                           $list_zip -f -d -k $feed_dir/$out_file
                done

}
function dom_feeds () {

		for list in "${c1fapp_lists_domain[@]}"
                do

                           c1fapp_feed="https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/domain_${list}/csv/"
                           out_file="domain_${list}.csv.gz"
                           echo "------Downloading ${out_file}------------"  
                           #echo "$(wget -r -N $c1fapp_feed $feed_dir/$out_file)"
                           echo "$(curl -R -f $c1fapp_feed --connect-timeout $timeout --keepalive --output $feed_dir/$out_file)"
                           $list_zip -f -d -k $feed_dir/$out_file
                done

}

function infra_feeds () {

		for list in "${c1fapp_lists_infra[@]}"
                       do
                           c1fapp_feeds="https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/infra_${list}/csv/"
                           out_file="infra_${list}.csv.gz"
                           echo "------Downloading ${out_file}------------"  
                           echo "$(curl -R -f $c1fapp_feeds --connect-timeout $timeout --keepalive --output $feed_dir/$out_file)"
                            $list_zip -f -d -k $feed_dir/$out_file
                        done

}

function url_feeds () {
		
		for list in "${c1fapp_lists_url[@]}" 	
			do	
				c1fapp_feeds="https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/url_${list}/csv/"
				out_file="url_${list}.csv.gz"
				echo "------Downloading ${out_file}------------"  
				echo $(curl -R -f  $c1fapp_feeds --connect-timeout $timeout --keepalive --output $feed_dir/$out_file) 
			 	$list_zip -f -d -k $feed_dir/$out_file
			done
		
}
function malware_feeds () {

		for list in "${c1fapp_lists_malware[@]}" 	
			do	
				c1fapp_feeds="https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/malware_${list}/csv/"
				out_file="malware_${list}.csv.gz"
				echo "------Downloading ${out_file}------------"  
				echo $(curl -R -f $c1fapp_feeds --connect-timeout $timeout --keepalive --output $feed_dir/$out_file) 
			 	$list_zip -f -d -k $feed_dir/$out_file
			done

}

function json_feeds () {

		for feed in "${c1fapp_feeds_json[@]}"
			do
				if [ $feed = "infra" ]
				then
					for list in "${c1fapp_lists_json_infra[@]}"
					do	
					 c1fapp_feeds_json="https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/${feed}_${list}/json/"
					 out_file="${feed}_${list}.json.gz"
                     echo "------Downloading ${out_file}------------"
                     echo "$(curl -R -f $c1fapp_feeds_json --connect-timeout $timeout --keepalive --output $feed_dir/$out_file)"
				     $list_zip -f -d -k $feed_dir/$out_file
					 done
				fi
		
				if [ $feed = "url" ]
				then
					for list in "${c1fapp_lists_json_url[@]}"
					do	
					 c1fapp_feeds_json="https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/${feed}_${list}/json/"
                     out_file="${feed}_${list}.json.gz"
                     echo "------Downloading ${out_file}------------"
                     echo "$(curl -R -f $c1fapp_feeds_json --connect-timeout $timeout --keepalive --output $feed_dir/$out_file)"
					 $list_zip -f -d -k $feed_dir/$out_file
					 done
				fi	
				if [ $feed = "domain" ]
                                then
				        for list in "${c1fapp_lists_json_domain[@]}"
                                        do
                         c1fapp_feeds_json="https://www.c1fapp.com${c1fapp_uri}/${saved_api_key}/${feed}_${list}/json/"
                         out_file="${feed}_${list}.json.gz"
                         echo "------Downloading ${out_file}------------"
                         echo "$(curl -R -f $c1fapp_feeds_json --connect-timeout $timeout --keepalive --output $feed_dir/$out_file)"
                         $list_zip -f -d -k $feed_dir/$out_file

                         done
				fi
			done

}

if [ "$#" == "-k" ] || [ "$#" == "-f" ];then
	OutputUsage
fi

while [ "$#" -gt "0" ]; do

	case "$1" in
	 -f|--file)
		saved_api_key="${2:-''}"
		if [ ! -f $saved_api_key ];then
			echo "Please provide a file that contains the key from C1fapp"	
			exit 1	
		else
		    c1fapp_dir

			exec 5<&0
			exec < "$2"	
			read key
			saved_api_key="$key"		
			check_AAA
			exec 0<&5 5<&-
			shift 2
		fi
	 ;;
	 -k|--key)
		saved_api_key="$2"
		if [ -z "$saved_api_key" ];then
			echo "Please provide a key from C1fapp"	
			exit 1	
		else
		    c1fapp_dir
            check_AAA
            echo "C1fapp Key is set"
			saved_api_key="${saved_api_key}"

			shift 2
		fi
	 ;;
	 -i|--infra)

	    check_AAA
		infra_feeds
		shift 1
		exit 1
	;;	
	-b|--bro)
	    check_AAA
		bro_feeds
		shift 1 
		exit 1
	;;
	-d|--dom)
	    check_AAA
		dom_feeds
		shift 1 
		exit 1
	;;	
	-u|--url)
	    check_AAA
		url_feeds
		shift 1 
		exit 1
	;;
	-j|--json)
	    check_AAA
		json_feeds
		shift 1 
		exit 1
	;;
	-a|--all)
	    check_AAA
	    c1fapp_dir
		infra_feeds
		dom_feeds
		url_feeds
		bro_feeds
		malware_feeds
		json_feeds
		shift 1
		exit 1
	;;	
	-V|--version)
	    flag="TRUE"
	    echo $version
	    shift 1
	    exit 1
	;;
	-h|--help|-*)
    	flag="TRUE"
	    OutputUsage
        exit 1
	
	break
	;;	
      esac	
done

	echo "Please choose a number to download list"	
	decoration
	select opt in $c1fapp_feeds; do

		#INFRA 
		if [ $opt = "infra" ]; then 
					
				infra_feeds
		#C1fapp Bro Ids combined
		elif [ $opt = "c1fapp_bro" ]; then

                    bro_feeds
		#DOMAIN
		elif [ $opt = "domain" ]; then 
			
				dom_feeds
		#URL	
		elif [ $opt = "url" ]; then 

				url_feeds	
		#Malware
		elif [ $opt = "malware" ]; then 

				malware_feeds
		#json 
		elif [ $opt = "json" ]; then 
			
				json_feeds			
	
		elif [ $opt = "ALL" ]; then 
			bro_feeds	
			infra_feeds
			dom_feeds
			url_feeds
			malware_feeds
			json_feeds

		else  
		
			clear 
			echo "Bad option"  	
			exit 1
		fi
	break
	done



