<?php

chdir(dirname(__FILE__));

require("../webroot/config.php");
require("../webroot/init.php");


function log_event($log) {
	global $m;

	$q = "INSERT INTO eventlog SET req_uri='". $m->escape_string(__FILE__) ."', log='". $m->escape_string($log) ."'";
	@$m->query($q) or die("$m->error\n$q\n");
}


if(($c = curl_init()) === FALSE)
	die("Failed to initialize cURL\n");

curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);


$t = time();
$num_checked = 0;
$num_found = 0;

$q = "SELECT onlinerainbowtables.id, hash, plaintext, hash_id, hashes.job_id FROM onlinerainbowtables LEFT JOIN hashes ON hash_id=hashes.id LEFT JOIN jobs ON job_id=jobs.id WHERE found=0 AND (dt_checked IS NULL OR dt_checked < DATE_SUB(NOW(), INTERVAL 2 DAY)) AND hashtype='raw-md5' ORDER BY dt_checked, id DESC";
if(($r = @$m->query($q)) === FALSE) 
	die("Failed to find hashes: $m->error\nSQL: $q\n");

while($row = $r->fetch_object()) {

	if(time() - $t > 550)
		break;

        // Make sure the hash isn't cracked already
	if($row->plaintext != NULL) {
                $q = "UPDATE onlinerainbowtables SET found=1, dt_checked=NOW() WHERE id='". $m->escape_string($row->id) ."'";
                if(@$m->query($q) === FALSE)  
                        die("Failed note hash as found in onlinerainbowtables: $m->error\nSQL: $q\n"); 

                continue;
        }


	curl_setopt($c, CURLOPT_URL, "http://md5.thekaine.de/index.php?hash=$row->hash");
	$data = curl_exec($c);
	if(preg_match('@<td colspan="2"><br><br><b>(.*)</b></td><td></td>@', $data, $matches)) {
		if(!empty($matches[1]) && !strstr($matches[1], "- not found")) {
			echo "md5.thekaine.de: found hash $row->hash [". $matches[1] ."]\n";

			$q = "INSERT INTO cracked_hashes SET node_id=-1, job_id='". $m->escape_string($row->job_id) ."', hash='". $m->escape_string($row->hash) ."', plaintext='". $m->escape_string($matches[1]) ."'";
			if(@$m->query($q) === FALSE)
				die("Failed insert into table cracked_hashes: $m->error\nSQL: $q\n");

			$q = "UPDATE onlinerainbowtables SET found=1, dt_checked=NOW() WHERE id='". $m->escape_string($row->id) ."'";
			if(@$m->query($q) === FALSE) 
				die("Failed note hash as found in onlinerainbowtables: $m->error\nSQL: $q\n");

			$num_checked++;
			$num_found++;
			continue;
		}
	}


	curl_setopt($c, CURLOPT_URL, "http://gdataonline.com/qkhash.php?mode=xml&hash=$row->hash");
	$data = curl_exec($c);
	if(preg_match('@<result>(.*)</result>@', $data, $matches)) {
		if(!empty($matches[1])) {
			echo "gdataonline.com: found hash $row->hash [". $matches[1] ."]\n";

			$q = "INSERT INTO cracked_hashes SET node_id=-1, job_id='". $m->escape_string($row->job_id) ."', hash='". $m->escape_string($row->hash) ."', plaintext='". $m->escape_string($matches[1]) ."'";
			if(@$m->query($q) === FALSE)
				die("Failed insert into table cracked_hashes: $m->error\nSQL: $q\n");

			$q = "UPDATE onlinerainbowtables SET found=1, dt_checked=NOW() WHERE id='". $m->escape_string($row->id) ."'";
			if(@$m->query($q) === FALSE) 
				die("Failed note hash as found in onlinerainbowtables: $m->error\nSQL: $q\n");

			$num_checked++;
			$num_found++;
			continue;
		}
	}


	curl_setopt($c, CURLOPT_URL, "http://us.md5.crysm.net/find?md5=$row->hash");
	$data = curl_exec($c);
	if(preg_match('@<li>(.*)</li>@', $data, $matches)) {
		if(!empty($matches[1])) {
			echo "us.md5.crysm.net: found hash $row->hash [". $matches[1] ."]\n";

			$q = "INSERT INTO cracked_hashes SET node_id=-1, job_id='". $m->escape_string($row->job_id) ."', hash='". $m->escape_string($row->hash) ."', plaintext='". $m->escape_string($matches[1]) ."'";
			if(@$m->query($q) === FALSE)
				die("Failed insert into table cracked_hashes: $m->error\nSQL: $q\n");

			$q = "UPDATE onlinerainbowtables SET found=1, dt_checked=NOW() WHERE id='". $m->escape_string($row->id) ."'";
			if(@$m->query($q) === FALSE) 
				die("Failed note hash as found in onlinerainbowtables: $m->error\nSQL: $q\n");

			$num_checked++;
			$num_found++;
			continue;
		}
	}


	$q = "UPDATE onlinerainbowtables SET dt_checked=NOW() WHERE id='". $m->escape_string($row->id) ."'";
	if(@$m->query($q) === FALSE) 
		die("Failed updaet dt_checked in onlinerainbowtables: $m->error\nSQL: $q\n");

	$num_checked++;
}

$r->close();

echo "Checked $num_checked in ". (time() - $t) ." seconds and found $num_found plaintexts\n";

?>
