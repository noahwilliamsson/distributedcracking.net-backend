<?php

chdir(dirname(__FILE__));

require("../webroot/config.php");
require("../webroot/init.php");


function log_event($log) {
	global $m;

	$q = "INSERT INTO eventlog SET req_uri='". $m->escape_string(__FILE__) ."', log='". $m->escape_string($log) ."'";
	@$m->query($q) or die("$m->error\n$q\n");
}




// Find all jobs which are active, cracking in incremental mode and have not run through its keyspace
$q = "SELECT id, jobname FROM jobs WHERE jobflags & (". (JOB_FLAG_ACTIVE | JOB_FLAG_INCREMENTAL | JOB_FLAG_INCREMENTAL_DONE) .") = ". (JOB_FLAG_ACTIVE | JOB_FLAG_INCREMENTAL);

$jobs = array();
$r = $m->query($q);
while($row = $r->fetch_object())
	$jobs[$row->id] = $row;
$r->close();


// Loop over each job
foreach($jobs as $job_id => $job) {

	// Fetch available packets for this job
	$q = "SELECT COUNT(*) num FROM packets WHERE job_id=$job_id AND completed IS NULL AND (acquired IS NULL or acquired < DATE_SUB(NOW(), INTERVAL 2 HOUR))";
	if(($r = $m->query($q)) == FALSE) {
		echo "ERROR: Failed to get number of free packets for job $job_id: $m->error\nSQL: $q\n";
		break;
	}
	else if(($row_packets = $r->fetch_object()) == NULL) {
		echo "ERROR: Zero rows returned while trying  get number of free packets for job $job_id: SQL: $q\n";
		break;
	}
	$r->close();


	echo "Job $job_id ($job->jobname) has $row_packets->num packets free packets\n";
	if($row_packets->num >= $incremental_min_available_packets) {

		continue;
	}


	// Figure out how many packets we need to generate
	$num_packets_to_generate = $incremental_num_free_packets_required - $row_packets->num;
	echo "- Need to generate $num_packets_to_generate new packets\n";



	// Fetch job information since things might have changed
	// since previous job's packets were genereated
	$q = "SELECT * FROM jobs WHERE id=$job_id";
	if(($r = @$m->query($q)) === FALSE || ($job = $r->fetch_object()) == NULL) {
		echo "ERROR: Failed to fetch job with tables locked: $job_id: $m->error\nSQL: $q\n";
		if($r)
			$r->close();
		continue;
	}
	$r->close();




	// Only incremental mode are supported for now
	if($attack_modes[$job->attack_mode]["mode"] != "incremental") {
		echo "- Job's (id $job_id) attack mode is not incremental, not supported yet!\n";
		echo "\n";
		continue;
	}


	// Default number of crypts for this hashtype (on a Pentium 4)
	$hashtype = strtolower($job->hashtype);
	if(!isset($incremental_packet_size[$hashtype])) {
		echo "ERROR: Unknown hash type '$hashtype' in \$incremental_packet_size for job with id $job_id\n";
		echo "\n";
		continue;
	}


	// Number of hashes that are "uncracked"
	$num_hashes_uncracked = $job->summary_numhashes - $job->summary_numcracked;
	if($num_hashes_uncracked <= 0) {
		echo "ERROR: Job with id $job_id is DONE!! Zero hashes.\n";
		echo "\n";
		continue;
	}


	// Calculate number of crypts with respect to the sought cracking time
	$rounds = $incremental_packet_size[$hashtype] * $incremental_avg_crack_time / $num_hashes_uncracked;

	// Fewer hashes have fewer salts which makes the cracking go faster..
	if($hash_type == "des" && $num_hashes < 10)
		$rounds = $rounds * 0.94;


	// We don't want the generator program to run for too long..
	$rounds = round($rounds);
	if($rounds > $incremental_max_num_rounds)
		$rounds = $incremental_max_num_rounds;



	// Generate those packets
	$incremental_params_this = $job->incremental_params_next;
	for($i = 0; $i < $num_packets_to_generate; $i++) {

		$cmdline = "";
		$cmdline .= escapeshellarg($incremental_path_generate) ." ";
		$cmdline .= escapeshellarg($attack_modes[$job->attack_mode]["options"]) ." ";
		foreach(explode("\t", $incremental_params_this, 3) as $arg) {
			$cmdline .= escapeshellarg($arg) ." ";
		}
		$cmdline .= "$rounds";


		echo "- $num_hashes_uncracked hashes, requested cracktime $incremental_avg_crack_time, rounds set to $rounds\n";
		echo "- Invoking $cmdline\n";
		$incremental_params_next = exec($cmdline, $fake_array, $ret);


		if($ret == 0 && strlen($incremental_params_next) > 10) {

			// Now, lock tables
			// - Make sure the job's incremental_params_next haven't changed 
			//   while the packet generator ran
			$q = "LOCK TABLES jobs WRITE, packets WRITE, eventlog WRITE";
			$m->query($q) or die("Failed to lock tables: $m->error\n");


			// When the tables are locked, fetch the current incremental_params_next
			$q = "SELECT incremental_params_next FROM jobs WHERE id=$job_id";
			if(($r = @$m->query($q)) === FALSE || ($job_current = $r->fetch_object()) == NULL) {
				echo "ERROR: Failed to fetch job information for job $job_id with tables locked: $m->error\nSQL: $q\n";
				if($r)
					$r->close();

				$q = "UNLOCK TABLES";
				$m->query($q);

				// Break out of this job's packet generation loop
				break;
			}
			$r->close();


			// Make sure they haven't changed
			if($job_current->incremental_params_next != $incremental_params_this) {
				echo "WARNING: Job's incremental_params_next changed from '$incremental_params_this' to '$job_current->incremental_params_next'\n";
				echo "WARNING: Generated packet ignored, skipping generating packet for this job\n";


				$q = "UNLOCK TABLES";
				$m->query($q);

				// Break out of this job's packet generation loop
				break;
			}



			$incremental_params_next = trim($incremental_params_next, "\n");


			// Add new packet
			$q = "INSERT INTO packets SET job_id=$job_id, num_hashes='". $m->escape_string($num_hashes_uncracked) ."', incremental_params='". $m->escape_string($incremental_params_this) ."', incremental_rounds='". $m->escape_string($rounds) ."'";
			if(@$m->query($q) === FALSE) {
				echo "ERROR: Failed to add new packet for job with id: $job_id: $m->error\nSQL: $q\n";
				break;
			}


			// Reflect changes in packets
			log_event("Job $job_id: incremental_params_next -> $incremental_params_next (was $incremental_params_this)");
			$q = "UPDATE jobs SET incremental_params_next='". $m->escape_string($incremental_params_next) ."', incremental_rounds_total = incremental_rounds_total + $rounds WHERE id=$job_id";
			if(@$m->query($q) === FALSE) {
				echo "ERROR: Failed to update incremental_params_next on job with id: $job_id: $m->error\nSQL: $q\n";
				break;

			}


			// Cache incremental_params_next data
			$incremental_params_this = $incremental_params_next;


			// Unlock tables 
			$q = "UNLOCK TABLES";
			$m->query($q);

		}
		else if($ret == 2) {
			// We've run through the whole keyspace (common in digits mode)
			$q = "UPDATE jobs SET jobflags = jobflags | ". (JOB_FLAG_INCREMENTAL_DONE) ." WHERE id=$job_id";
			if(@$m->query($q) === FALSE) {
				echo "ERROR: Failed to mark job $job_id as done due to out of packets: $m->error\nSQL: $q\n";

				// Break out of this job's packet generation loop
				break;
			}
		}
		else {
			echo "ERROR: Command returned $ret, output was: $incremental_params_next\n";

			// Break out of this job's packet generation loop
			break;
		}

		echo "- Packet ". ($i+1) ."/$num_packets_to_generate generated. ret=$ret, new param: $incremental_params_next\n";
	}

	echo "\n";	


}


?>
