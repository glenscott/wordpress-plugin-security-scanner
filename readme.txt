=== Plugin Security Scanner ===
Contributors: glen_scott
Tags: plugins,security,scanner,vulnerabilities,secure
Tested up to: 4.2
Stable tag: 1.1.5
License: GPLv2 or later

This plugin alerts you if any of your plugins have security vulnerabilities.  It does this by utilising the WPScan Vulnerability Database once a day.

== Description ==

This plugin determines whether any of your plugins have security vulnerabilities.  It does this by looking up details in the WPScan Vulnerability Database.

It will run a scan once a day, and e-mail the administrator if any vulnerable plugins are found.

It also adds a new menu option to the admin tools menu called "Plugin Security Scanner".  Clicking this runs a scan.  If the scan finds any problems, it shows you a list of plugins that have vulnerabilities, along with a description of the issue.

Icons made by <a href="http://www.flaticon.com/authors/alessio-atzeni" title="Alessio Atzeni">Alessio Atzeni</a> from <a href="http://www.flaticon.com" title="Flaticon">www.flaticon.com</a> is licensed by <a href="http://creativecommons.org/licenses/by/3.0/" title="Creative Commons BY 3.0">CC BY 3.0</a>

== Screenshots ==

1. Example run of the security scanner that has found two vulnerable plugins.

== Changelog ==

= 1.1.5 =
* Escape output in HTML report to prevent XSS

= 1.1.4 =
* Added blog title to email subject

= 1.1.3 =
* Fixed bug that prevented admin email being sent

= 1.1 =
* Email admin daily if any vulnerabilities are found

= 1.0 =
* Initial release

