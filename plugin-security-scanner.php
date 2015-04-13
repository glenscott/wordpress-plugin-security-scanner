<?php

/**
 * Plugin Name: Plugin Security Scanner
 * Plugin URI: http://www.glenscott.co.uk/plugin-security-scanner/
 * Description: This plugin determines whether any of your plugins have security vulnerabilities.  It does this by looking up details in the WPScan Vulnerability Database. 
 * Version: 1.0
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

if( !class_exists( 'WP_Http' ) )
    include_once( ABSPATH . WPINC. '/class-http.php' );

/** Step 2 (from text above). */
add_action( 'admin_menu', 'my_plugin_menu' );

/** Step 1. */
function my_plugin_menu() {
    add_management_page( 'Plugin Security Scanner', 'Plugin Security Scanner', 'manage_options', 'plugin-security-scanner', 'my_plugin_options' );
}

/** Step 3. */
function my_plugin_options() {
    if ( !current_user_can( 'manage_options' ) )  {
        wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
    }
    echo '<div class="wrap">';
    echo '<h2>Plugin Security Scanner</h2>';

    $request = new WP_Http;

    $vulnerability_count = 0;

    foreach (get_plugins() as $name => $details) {
        // get unique name 
        if (preg_match('|(.+)/|', $name, $matches)) {
            $result = $request->request( 'https://wpvulndb.com/api/v1/plugins/' . $matches[1] );

            if ($result['body']) {
                $plugin = json_decode($result['body']);

                if (isset($plugin->plugin->vulnerabilities)) {
                    foreach ($plugin->plugin->vulnerabilities as $vuln) {
                        if (version_compare($details['Version'], $vuln->fixed_in, '<')) {
                            echo "<p><strong>Vulnerability found:</strong> " . $vuln->title . "</p>";
                            //echo '<p><a href="' . admin_url() . 'update.php?action=upgrade-plugin&plugin=' . $name . '&_wpnonce=' . wp_create_nonce() . '">Update now</a></p>';

                            $vulnerability_count++;
                        }
                    }
                }
            }
            ob_flush();
            flush();
        }
    }

    // if (!$vulnerability_count) {
    //     echo '<p>No vulnerable plugins found.</p>';
    // }
    echo '<p>Scan completed:  <strong>' . $vulnerability_count . '</strong> vulnerabilit' . ($vulnerability_count == 1 ? 'y' : 'ies') .  ' found.</p>';
    echo '</div>';
}