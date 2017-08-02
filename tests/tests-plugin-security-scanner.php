<?php
/**
 * Class SampleTest
 *
 * @package Plugin_Security_Scanner
 */

/**
 * Sample test case.
 */
class PluginSecurityScannerTests extends WP_HTTP_TestCase {

	const WEB_HOOK_URL = 'http://webhook.com';

	/**
	 * @test
	 */
	function get_vulnerable_plugins_vulndb_network_error_trigger_error() {
		$this->http_responder = array( $this, 'mock_server_response_network_error' );
		$this->setExpectedException('PHPUnit_Framework_Error');

		get_vulnerable_plugins();
	}

	/**
	 * @test
	 */
	function get_vulnerable_plugins_vulndb_status_code_invalid_trigger_error() {
		$this->http_responder = array( $this, 'mock_server_response' );
		$this->setExpectedException('PHPUnit_Framework_Error');

		get_vulnerable_plugins();
	}

	/**
	 * @test
	 */
	function get_vulnerable_plugins_query_vulndb_with_wp_version_plugins_themes() {
		$plugins_count = 0;
		foreach ( get_plugins() as $name => $details ) {
			// get unique name
			if ( preg_match( '|(.+)/|', $name, $matches ) ) {
				$plugins_count += 1;
			}
		}

		$themes_count = count(wp_get_themes());
		get_vulnerable_plugins();
		$this->assertCount( $plugins_count + $themes_count + 1, $this->http_requests );
	}

	/**
	 * @test
	 */
	function get_vulnerable_plugins_return_vulndb_response() {
		$this->http_responder = array( $this, 'mock_server_response_valid' );

		$result = get_vulnerable_plugins();

		$this->assertCount( 1,  $result );
	}

	/**
	 * @test
	 */
	function on_activate_register_daily_hook() {
		plugin_security_scanner_activation();

		$schedule = wp_get_schedule( 'plugin_security_scanner_daily_event_hook' );

		$this->assertEquals('daily', $schedule);
	}

	/**
	 * @test
	 */
	function plugin_security_scanner_do_this_daily_email_enabled_send_mail_with_vuln() {
		$admin_email = 'admin@test.com';
		$this->http_responder = array( $this, 'mock_server_response_valid' );
		update_option( 'plugin-security-scanner', array(
			 'email_notification' => '1',
			 'webhook_notification' => '0',
			 'webhook_notification_url' => '') );
		update_option( 'admin_email', $admin_email );

		plugin_security_scanner_do_this_daily();

		$email = tests_retrieve_phpmailer_instance()->get_sent();
		$this->assertEquals( array( array( $admin_email, '' ) ), $email->to );
		$this->assertNotEmpty($email->body);
	}

	/**
	 * @test
	 */
	function plugin_security_scanner_do_this_daily_webhook_enabled_call_webhook_with_vuln() {
		$admin_email = 'admin@test.com';
		$this->http_responder = array( $this, 'mock_server_response_valid' );
		update_option( 'plugin-security-scanner', array(
			 'email_notification' => '0',
			 'webhook_notification' => '1',
			 'webhook_notification_url' => self::WEB_HOOK_URL) );
		update_option( 'admin_email', $admin_email );

		plugin_security_scanner_do_this_daily();

		$called = false;

		foreach ( $this->http_requests as $request ) {
			// get unique name
			if ( $request['url'] ==  self::WEB_HOOK_URL) {
				$called = true;
			}
		}

		$this->assertTrue($called);
	}

	protected function mock_server_response_invalid_status_code( $request, $url ) {
		return array( 'body' => 'Test response.', 'response' => array('code' => 400));
	}

	protected function mock_server_response_network_error( $request, $url ) {
		return new WP_Error( 'broke', __( "I've fallen and can't get up", "my_textdomain" ) );
	}

	protected function mock_server_response_valid( $request, $url ) {
		global $wp_version;
		$version_trimmed = str_replace(".", "", $wp_version);
		if ($url == "https://wpvulndb.com/api/v2/wordpresses/".$version_trimmed){
			$response = file_get_contents(dirname( dirname( __FILE__ ) ) . '/tests/wpvulndbapi_res.json', true);
			$response = str_replace("{{wordpress_version}}", $wp_version, $response);
			return array( 'body' => $response, 'response' => array('code' => 200));
		} else if ($url == self::WEB_HOOK_URL){
			return array( 'body' => '', 'response' => array('code' => 200));
		}

		return array( 'body' => '', 'response' => array('code' => 200));
	}

}
