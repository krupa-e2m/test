<?php

defined( 'ABSPATH' ) || exit;

class Dev_Connect_Settings {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_page' ) );
	}

	public static function add_page() {
		add_options_page( 'DEV Connect', 'DEV Connect', 'manage_options', 'dev-connect', array( __CLASS__, 'render' ) );
	}

	public static function render() {
		echo '<div class="wrap"><h1>DEV Connect</h1><p>Settings will appear here.</p></div>';
	}
}
