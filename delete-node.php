<?php

	require("../config.php");
	require("../init.php");

	if($argc != 2) {
		die("Usage: ". $argv[0] ." <node id>\n");
	}

	$node_id = $argv[1];

	$q = "SELECT * FROM nodes WHERE id='". $m->escape_string($node_id) ."'";
	$r = $m->query($q);
	if(($row = $r->fetch_object()) != NULL) {
		$q = "DELETE FROM nodes WHERE id=". $row->id;
		$m->query($q);

		// XXX - How handle packets with that node_id?

		echo "Node $node_id deleted\n";

	}
	else
		echo "Node $node_id not found\n";
	$r->close();

?>
