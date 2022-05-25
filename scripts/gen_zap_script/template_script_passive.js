/*
 * Jinja-injected parameters
 */

var params = {{ params | tojson | safe }} ;

{% include "template_script_functions.js" %}

/**
 * Passively scans an HTTP message. The scan function will be called for
 * request/response made via ZAP, actual messages depend on the function
 * "appliesToHistoryType", defined below.
 *
 * @param ps - the PassiveScan parent object that will do all the core interface tasks
 *     (i.e.: providing access to Threshold settings, raising alerts, etc.).
 *     This is an ScriptsPassiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param src - the Jericho Source representation of the message being scanned.
 */
function scan(ps, msg, src) {
	let searchInText = getSearchInText(msg, params.searchIn);
	let matching = findRegExpInString(searchInText, regexpLiteralValidation(params.regexp));

	if (matching) {
		createAlert(ps, msg, params.finding, matching['regexp'] + '\t|\t' + matching['found'])
			.raise();
	}
}
