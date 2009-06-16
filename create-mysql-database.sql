-- MySQL dump 10.11
--

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `archived_hashes`
--

DROP TABLE IF EXISTS `archived_hashes`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `archived_hashes` (
  `id` int(11) NOT NULL auto_increment,
  `node_id` int(11) default NULL,
  `job_id` int(11) default NULL,
  `hash` varchar(48) default NULL,
  `plaintext` varchar(32) character set utf8 collate utf8_bin default NULL,
  `dt_cracked` datetime default NULL,
  PRIMARY KEY  (`id`),
  KEY `hash` (`hash`(8))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `archived_jobs`
--

DROP TABLE IF EXISTS `archived_jobs`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `archived_jobs` (
  `id` int(11) NOT NULL auto_increment,
  `owner_user_id` int(11) default NULL,
  `jobname` varchar(64) default NULL,
  `hashtype` varchar(16) default NULL,
  `attack_mode` tinyint(3) unsigned default '10',
  `jobflags` tinyint(3) unsigned default '0',
  `jobcookie` varchar(32) default NULL,
  `dt_created` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `dt_lastactive` datetime default NULL,
  `summary_numhashes` int(11) unsigned NOT NULL default '0',
  `summary_numcracked` int(11) unsigned NOT NULL default '0',
  `incremental_params_next` varchar(255) NOT NULL default '0	0,0,0,0,0,0,0,0	0,0,-1,-1,-1,',
  `incremental_rounds_total` bigint(20) unsigned NOT NULL default '0',
  `wordlist_params_next` varchar(20) NOT NULL default '1,1',
  `wordlist_rounds_total` int(11) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`),
  KEY `owner_user_id` (`owner_user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `archived_packets`
--

DROP TABLE IF EXISTS `archived_packets`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `archived_packets` (
  `id` int(11) NOT NULL auto_increment,
  `job_id` int(11) NOT NULL default '0',
  `node_id` int(11) NOT NULL default '0',
  `num_hashes` int(11) unsigned NOT NULL default '0',
  `incremental_params` varchar(64) NOT NULL,
  `incremental_rounds` bigint(20) unsigned NOT NULL default '0',
  `wordlist_params` varchar(20) default NULL,
  `wordlist_rounds` int(11) default NULL,
  `done` tinyint(1) NOT NULL default '0',
  `acquired` datetime default NULL,
  `completed` datetime default NULL,
  PRIMARY KEY  (`id`),
  KEY `job_id` (`node_id`),
  KEY `node_id` (`job_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `autherrors`
--

DROP TABLE IF EXISTS `autherrors`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `autherrors` (
  `id` int(11) NOT NULL auto_increment,
  `ts` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  `user` varchar(32) default NULL,
  `pass` varchar(32) default NULL,
  `ip` varchar(64) default NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `cracked_hashes`
--

DROP TABLE IF EXISTS `cracked_hashes`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `cracked_hashes` (
  `id` int(11) NOT NULL auto_increment,
  `node_id` int(11) default NULL,
  `job_id` int(11) default '0',
  `dt_submitted` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `hash` varchar(48) character set utf8 collate utf8_bin default NULL,
  `plaintext` varchar(32) character set utf8 collate utf8_bin default NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `eventlog`
--

DROP TABLE IF EXISTS `eventlog`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `eventlog` (
  `id` int(11) NOT NULL auto_increment,
  `dt_event` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `user_id` int(11) default NULL,
  `ip` varchar(64) default NULL,
  `useragent` varchar(255) default NULL,
  `req_uri` varchar(255) default NULL,
  `log` text,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `group_jobs`
--

DROP TABLE IF EXISTS `group_jobs`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `group_jobs` (
  `group_id` int(11) NOT NULL default '0',
  `job_id` int(11) NOT NULL default '0',
  PRIMARY KEY  (`group_id`,`job_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `group_members`
--

DROP TABLE IF EXISTS `group_members`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `group_members` (
  `id` int(11) NOT NULL auto_increment,
  `group_id` int(11) default NULL,
  `user_id` int(11) default NULL,
  `group_admin` tinyint(1) NOT NULL default '0',
  `dt_added` timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY  (`id`),
  UNIQUE KEY `group_user` (`user_id`,`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `groups`
--

DROP TABLE IF EXISTS `groups`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `groups` (
  `id` int(11) NOT NULL auto_increment,
  `groupname` varchar(32) default NULL,
  `invite_code` varchar(32) default NULL,
  `dt_created` timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `hashes`
--

DROP TABLE IF EXISTS `hashes`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `hashes` (
  `id` int(11) NOT NULL auto_increment,
  `node_id` int(11) default NULL,
  `job_id` int(11) default NULL,
  `hash` varchar(48) character set utf8 collate utf8_bin default NULL,
  `plaintext` varchar(32) character set utf8 collate utf8_bin default NULL,
  `dt_cracked` datetime default NULL,
  PRIMARY KEY  (`id`),
  KEY `hash` (`hash`(8))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `invites`
--

DROP TABLE IF EXISTS `invites`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `invites` (
  `id` int(11) default NULL,
  `user_id` int(11) default NULL,
  `code` varchar(32) default NULL,
  `dt_created` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `dt_accepted` datetime default NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `jobrequests`
--

DROP TABLE IF EXISTS `jobrequests`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `jobrequests` (
  `id` int(11) NOT NULL auto_increment,
  `job_id` int(11) NOT NULL default '0',
  `node_id` int(11) NOT NULL default '0',
  `dt_requested` timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `jobs`
--

DROP TABLE IF EXISTS `jobs`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `jobs` (
  `id` int(11) NOT NULL auto_increment,
  `owner_user_id` int(11) default NULL,
  `jobname` varchar(64) default NULL,
  `hashtype` varchar(16) default NULL,
  `attack_mode` tinyint(3) unsigned default '10',
  `jobflags` tinyint(3) unsigned default '0',
  `jobcookie` varchar(32) default NULL,
  `dt_created` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `dt_lastactive` datetime default NULL,
  `summary_numhashes` int(11) unsigned NOT NULL default '0',
  `summary_numcracked` int(11) unsigned NOT NULL default '0',
  `incremental_params_next` varchar(255) NOT NULL default '0	0,0,0,0,0,0,0,0	0,0,-1,-1,-1,',
  `incremental_rounds_total` bigint(20) unsigned NOT NULL default '0',
  `wordlist_params_next` varchar(20) NOT NULL default '1,1',
  `wordlist_rounds_total` int(11) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`),
  KEY `owner_user_id` (`owner_user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `nodes`
--

DROP TABLE IF EXISTS `nodes`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `nodes` (
  `id` int(11) NOT NULL auto_increment,
  `user_id` int(11) NOT NULL default '0',
  `current_job_id` int(11) NOT NULL default '0',
  `nodename` varchar(32) default NULL,
  `cpuinfo` varchar(255) default NULL,
  `useragent` varchar(40) default NULL,
  `dt_created` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `dt_lastactive` datetime default NULL,
  `ciphers` text,
  `authcookie` varchar(32) default NULL,
  PRIMARY KEY  (`id`),
  KEY `user_id` (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `onlinerainbowtables`
--

DROP TABLE IF EXISTS `onlinerainbowtables`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `onlinerainbowtables` (
  `id` int(11) NOT NULL auto_increment,
  `hash_id` int(11) NOT NULL default '0',
  `found` tinyint(1) default '0',
  `dt_added` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `dt_checked` datetime default NULL,
  `dt_irc` datetime default NULL,
  PRIMARY KEY  (`id`),
  KEY `found` (`found`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `packets`
--

DROP TABLE IF EXISTS `packets`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `packets` (
  `id` int(11) NOT NULL auto_increment,
  `job_id` int(11) NOT NULL default '0',
  `node_id` int(11) NOT NULL default '0',
  `num_hashes` int(11) unsigned NOT NULL default '0',
  `incremental_params` varchar(64) NOT NULL,
  `incremental_rounds` bigint(20) unsigned NOT NULL default '0',
  `wordlist_params` varchar(20) default NULL,
  `wordlist_rounds` int(11) default NULL,
  `done` tinyint(1) NOT NULL default '0',
  `acquired` datetime default NULL,
  `completed` datetime default NULL,
  PRIMARY KEY  (`id`),
  KEY `job_id` (`node_id`),
  KEY `node_id` (`job_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `plaintexts_info`
--

DROP TABLE IF EXISTS `plaintexts_info`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `plaintexts_info` (
  `id` int(11) NOT NULL auto_increment,
  `word` varchar(32) character set utf8 collate utf8_bin NOT NULL default '',
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `sessioncache`
--

DROP TABLE IF EXISTS `sessioncache`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `sessioncache` (
  `id` int(11) NOT NULL auto_increment,
  `user_id` int(11) NOT NULL default '0',
  `session` text,
  PRIMARY KEY  (`id`),
  KEY `user_id` (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `users` (
  `id` int(11) NOT NULL auto_increment,
  `username` varchar(32) default NULL,
  `password` varchar(32) default NULL,
  `dt_created` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `dt_lastlogin` datetime default NULL,
  `invites_earned` tinyint(4) unsigned NOT NULL default '0',
  `invites_sent` tinyint(4) unsigned NOT NULL default '0',
  `user_flags` tinyint(4) unsigned NOT NULL default '0',
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `wordlist`
--

DROP TABLE IF EXISTS `wordlist`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `wordlist` (
  `id` int(11) NOT NULL auto_increment,
  `word` varchar(32) character set utf8 collate utf8_bin NOT NULL default '',
  `hits` int(11) NOT NULL default '1',
  `dt_added` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  PRIMARY KEY  (`id`),
  KEY `word` (`word`(4))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `wordlist_packets`
--

DROP TABLE IF EXISTS `wordlist_packets`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `wordlist_packets` (
  `id` int(11) NOT NULL auto_increment,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `wordlist_revision_map`
--

DROP TABLE IF EXISTS `wordlist_revision_map`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `wordlist_revision_map` (
  `id` int(11) NOT NULL auto_increment,
  `revision` smallint(6) default '0',
  `wordlist_id` int(11) NOT NULL default '0',
  `new_since_last_revision` tinyint(1) NOT NULL default '0',
  PRIMARY KEY  (`id`),
  UNIQUE KEY `revision` (`revision`,`wordlist_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `wordlist_revisions`
--

DROP TABLE IF EXISTS `wordlist_revisions`;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8;
CREATE TABLE `wordlist_revisions` (
  `id` int(11) NOT NULL auto_increment,
  `summary_numwords` int(11) default '0',
  `dt_created` timestamp NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
SET character_set_client = @saved_cs_client;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
