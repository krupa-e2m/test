<?php
/**
 * Plugin Name: DEV Connect
 * Description: Connects this site to DEV Command.
 * Version:     0.1.0
 */

defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/includes/class-settings.php';

add_action( 'plugins_loaded', array( 'Dev_Connect_Settings', 'init' ) );
