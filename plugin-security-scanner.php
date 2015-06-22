<?php

/**
 * Plugin Name: Plugin Security Scanner
 * Plugin URI: http://www.glenscott.co.uk/plugin-security-scanner/
 * Description: This plugin determines whether any of your plugins have security vulnerabilities.  It does this by looking up details in the WPScan Vulnerability Database.
 * Version: 1.1.9
 * Author: Glen Scott
 * Author URI: http://www.glenscott.co.uk
 * License: GPL2
 */

/*  Copyright 2015  Glen Scott  (email : glen@glenscott.co.uk)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License, version 2, as
	published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

if ( ! class_exists( 'WP_Http' ) ) {
	include_once( ABSPATH . WPINC. '/class-http.php' );
}

// Check if get_plugins() function exists. This is required on the front end of the
// site, since it is in a file that is normally only loaded in the admin.
if ( ! function_exists( 'get_plugins' ) ) {
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
}

/** Step 2 (from text above). */
add_action( 'admin_menu', 'plugin_security_scanner_menu' );

/** Step 1. */
function plugin_security_scanner_menu() {
	add_management_page( 'Plugin Security Scanner', 'Plugin Security Scanner', 'manage_options', 'plugin-security-scanner', 'plugin_security_scanner_options' );
}

/** Step 3. */
function plugin_security_scanner_options() {
	if ( ! current_user_can( 'manage_options' ) )  {
		wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
	}
	echo '<div class="wrap">';
	echo '<h2>Plugin Security Scanner</h2>';

	$request = new WP_Http;

	$vulnerability_count = 0;

	foreach ( get_plugins() as $name => $details ) {
		// get unique name
		if ( preg_match( '|(.+)/|', $name, $matches ) ) {
			$result = $request->request( 'https://wpvulndb.com/api/v1/plugins/' . $matches[1] );

			if ( $result['body'] ) {
				$plugin = json_decode( $result['body'] );

				if ( isset( $plugin->plugin->vulnerabilities ) ) {
					foreach ( $plugin->plugin->vulnerabilities as $vuln ) {
						if ( ! isset($vuln->fixed_in) ||
							version_compare( $details['Version'], $vuln->fixed_in, '<' ) ) {
							echo '<p><strong>Vulnerability found:</strong> ' . esc_html( $vuln->title ) . ' -- <a href="' . esc_url( 'https://wpvulndb.com/vulnerabilities/' . $vuln->id ) . '" target="_blank">View details</a></p>';

							$vulnerability_count++;
						}
					}
				}
			}
			flush();
		}
	}

	echo '<p>Scan completed:  <strong>' . esc_html( $vulnerability_count ) . '</strong> vulnerabilit' . esc_html( ( $vulnerability_count == 1 ? 'y' : 'ies') ) .  ' found.</p>';
	echo '</div>';
}

// scheduled email to admin
register_activation_hook( __FILE__, 'plugin_security_scanner_activation' );
/**
 * On activation, set a time, frequency and name of an action hook to be scheduled.
 */
function plugin_security_scanner_activation() {
	wp_schedule_event( time(), 'daily', 'plugin_security_scanner_daily_event_hook' );
}

add_action( 'plugin_security_scanner_daily_event_hook', 'plugin_security_scanner_do_this_daily' );
/**
 * On the scheduled action hook, run the function.
 */
function plugin_security_scanner_do_this_daily() {
	$admin_email = get_option( 'admin_email' );

	if ( $admin_email ) {
		$mail_body = '';

		// run scan
		$request = new WP_Http;
		$vulnerability_count = 0;

		foreach ( get_plugins() as $name => $details ) {
			// get unique name
			if ( preg_match( '|(.+)/|', $name, $matches ) ) {
				$result = $request->request( 'https://wpvulndb.com/api/v1/plugins/' . $matches[1] );

				if ( $result['body'] ) {
					$plugin = json_decode( $result['body'] );

					if ( isset( $plugin->plugin->vulnerabilities ) ) {
						foreach ( $plugin->plugin->vulnerabilities as $vuln ) {
							if ( ! isset($vuln->fixed_in) ||
								version_compare( $details['Version'], $vuln->fixed_in, '<' ) ) {
								$mail_body .= 'Vulnerability found: ' . $vuln->title . "\n";
								$vulnerability_count++;
							}
						}
					}
				}
			}
		}

		// if vulns, email admin
		if ( $vulnerability_count ) {
			$mail_body .= "\n\n" . 'Scan completed:  ' . $vulnerability_count . ' vulnerabilit' . ($vulnerability_count == 1 ? 'y' : 'ies') .  ' found.' . "\n";

			wp_mail( $admin_email, get_bloginfo() . ' Plugin Security Scan ' . date_i18n( get_option( 'date_format' ) ), $mail_body );
		}
	}
}

register_deactivation_hook( __FILE__, 'prefix_deactivation' );
/**
 * On deactivation, remove all functions from the scheduled action hook.
 */
function prefix_deactivation() {
	wp_clear_scheduled_hook( 'plugin_security_scanner_daily_event_hook' );
}
