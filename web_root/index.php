<?php
	error_reporting(E_ALL|E_STRICT);
	ini_set('display_errors', true);
	date_default_timezone_set('Europe/London');
	
	$rootDir = dirname(dirname(__FILE__));
	set_include_path($rootDir . '/library' . PATH_SEPARATOR . get_include_path());
	
	require_once 'Zend/Controller/Front.php';
	Zend_Controller_Front::run('../application/controllers');

?>