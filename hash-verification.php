<?php

chdir(dirname(__FILE__));

require("../webroot/config.php");
require("../webroot/init.php");


$m->query("SET names latin1");

function log_event($log) {
	global $m;

	$q = "INSERT INTO eventlog SET req_uri='". $m->escape_string(__FILE__) ."', log='". $m->escape_string($log) ."'";
	@$m->query($q) or die("$m->error\n$q\n");
}


function verify_and_update() {
	global $m;
	global $hash_states;

	$ts_begin = time(); 
	@unlink("./john.pot");

	if(!file_exists("passwd") || !file_exists("wordlist"))
		return;

	$cmdline = "./john -w:./wordlist ./passwd";
	exec($cmdline, $output, $ret);
	if($ret != 0)
		die("Failed to execute $cmdline. Ret = $ret, output was: $output\n");

	$ts_elapsed = time() - $ts_begin;

	array_shift($output);
	foreach($output as $l) {
		// XXX v1 if(preg_match('/\((\d+)\)$/', $l, $matches) != 1) {
		if(preg_match('/\((\d+)=\d+\)$/', $l, $matches) != 1) {
			echo "WTF, zero hits on '$l'\n";
			continue;
		}

		$hash_states[$matches[1]] = TRUE;
	}

	foreach($hash_states as $id => $valid) {
		if($valid == FALSE) {
			// This can happen because of dupes or invalid hashes
			$q = "UPDATE cracked_hashes SET id=-'". $m->escape_string($id) ."' WHERE id='". $m->escape_string($id) ."'";
			if(@$m->query($q) === FALSE)
				die("Failed mark hash as invalid: $m->error\nSQL: $q\n");
			continue;
		}


		// Fetch plaintext and hash for this id
		$q = "SELECT hash, plaintext, node_id, dt_submitted FROM cracked_hashes WHERE id='". $m->escape_string($id) ."'";
		if(($rp = @$m->query($q)) === FALSE)
			die("Failed to get plaintext: $m->error\nSQL: $q\n");
		else if(($cracked_hash = $rp->fetch_object()) == NULL) {
			// This hash might have been removed already
			// XXX - don't remember the exact details here.. hmm
			$rp->close();
			continue;
		}
		$rp->close();

		
		// Look for uncracked hashes with this hash
		$q = "SELECT id, job_id FROM hashes WHERE hash='". $m->escape_string($cracked_hash->hash) ."' AND plaintext IS NULL";
		if(($r_uncracked = @$m->query($q)) === FALSE)
			die("Failed find uncracked hashes: $m->error\nSQL: $q\n");


		$affected_jobs = array();

		while($row = $r_uncracked->fetch_object()) {
			$q = "UPDATE hashes SET plaintext='". $m->escape_string($cracked_hash->plaintext) ."', dt_cracked='".  $m->escape_string($cracked_hash->dt_submitted) ."', node_id='". $m->escape_string($cracked_hash->node_id) ."' WHERE id='". $m->escape_string($row->id) ."'";
			if(@$m->query($q) === FALSE)
				die("Failed update table hashes: $m->error\nSQL: $q\n");



			$q = "UPDATE jobs SET summary_numcracked=summary_numcracked+1 WHERE id='". $m->escape_string($row->job_id) ."'";
			if(@$m->query($q) === FALSE)
				die("Failed update cracked count for job: $m->error\nSQL: $q\n");


			if(!in_array($row->job_id, $affected_jobs))
				$affected_jobs[] = $row->job_id;

		}
		$r_uncracked->close();


		// Check if all hashes are cracked
		foreach($affected_jobs as $job_id) {
			$q = "SELECT summary_numhashes, summary_numcracked, jobflags FROM jobs WHERE id='". $m->escape_string($job_id) ."'";
			if(($r_job = @$m->query($q)) === FALSE)
				die("Failed fetch summary info for job: $m->error\nSQL: $q\n");
			else if(($row = $r_job->fetch_object()) == NULL)
				die("Failed fetch summary info for job (zero rows): $m->error\nSQL: $q\n");

			$r_job->close();

			if($row->summary_numcracked < $row->summary_numhashes)
				continue;

			// Mark job as done
			$jobflags = $row->jobflags;
			$jobflags |= JOB_FLAG_DONE;
			$jobflags &= ~JOB_FLAG_ACTIVE;
			echo "Marking job $job_id as done (prev: $row->jobflags, new: $jobflags)\n";
			$q = "UPDATE jobs SET jobflags=$jobflags WHERE id='". $m->escape_string($job_id) ."'";
			if(@$m->query($q) == FALSE) 
				die("Failed to mark job as done: $m->error\nSQL: $q\n");
		}


		$q = "DELETE FROM cracked_hashes WHERE id='". $m->escape_string($id) ."'";
		if(@$m->query($q) === FALSE)
			die("Failed to remove valid hash from cracked_hashes: $m->error\nSQL: $q\n");

		if(($fd = fopen("/tmp/cracked.txt", "at")) !== FALSE) {
			fwrite($fd, "Deleted cracked_hashes.id=$id\t$cracked_hash->hash\t$cracked_hash->plaintext\n");
			fclose($fd);
		}
		


	} // foreach hash state
}


if(chdir($hash_verification_jtr_root) == FALSE) 
	die("Failed to change directory to $hash_verification_jtr_root\n");


// Find previously cracked hashes 
// Hashes with a negative id number are invalid and aren't loaded
$q = "SELECT cracked_hashes.*, jobs.hashtype FROM cracked_hashes LEFT JOIN jobs ON job_id=jobs.id WHERE cracked_hashes.id > 0 ORDER BY hashtype, dt_submitted LIMIT 10000";
if(($r = @$m->query($q)) === FALSE)
	die("Failed to fetch cracked hashes: $m->error\nSQL: $q\n");

$current_hashtype = "";
$current_num = 0;
$wordlist = NULL;
$passwd = NULL;
$hash_states = array();
$unique_counter = 0;
while($row = $r->fetch_object()) {
	$unique_counter++;

	// The standalone cracker which only reports hashes and plaintexts needs special consideration
	if($row->job_id == 0) {
		$q = "SELECT hashtype FROM hashes LEFT JOIN jobs ON job_id=jobs.id WHERE hash='". $m->escape_string($row->hash) ."' LIMIT 1";
		$r_hashtype_lookup = $m->query($q);
		if(($hashtype_lookup = $r_hashtype_lookup->fetch_object()) != NULL)
			$row->hashtype = $hashtype_lookup->hashtype;
		$r_hashtype_lookup->close();

		if(empty($row->hashtype)) {
			//echo "WARNING: Cracked hash '$row->hash' not found among uploaded hashes.\n";
			continue;
		}
	}

	// On the first run we need to open passwd and wordlist files and set the current hashtype
	// If the current hashtype we're processing differ from this row's hashtype we need
	// to close the passwd and wordlist files and start verifying hashes, before starting
	// over with new passwd and wordlist files
	if(empty($current_hashtype) || $row->hashtype != $current_hashtype) {
		if(!empty($current_hashtype)) {
			fclose($wordlist);
			fclose($passwd);
			verify_and_update();
			$current_num = 0;
		}

		$hash_states = array();
		$current_hashtype = $row->hashtype;

		if(($wordlist = fopen($hash_verification_jtr_root ."wordlist", "w")) === FALSE)
			die("Failed to open $hash_verification_jtr_root"."wordlist for writing.\n");
		if(($passwd = fopen($hash_verification_jtr_root ."passwd", "w")) === FALSE)
			die("Failed to open $hash_verification_jtr_root"."passwd for writing.\n");
	}

	if($row->hashtype == $current_hashtype) {
		$current_num++;
		fprintf($wordlist, "%s\n", $row->plaintext);
		fprintf($passwd, "%d=%d:%s\n", $row->id, $unique_counter, $row->hash);

		// Default to invalid
		$hash_states[$row->id] = FALSE;
	}
};

if($r->num_rows) {
	if($wordlist != NULL)
		fclose($wordlist);
	if($password != NULL)
		fclose($passwd);
	verify_and_update();
}

$r->close();
?>
