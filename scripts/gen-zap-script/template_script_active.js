// Jinja injected parameters for this script
var params = {{ params | tojson | safe }} ;

{% include "template_script_functions.js" %}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 *
 * @param as - the ActiveScan parent object that will do all the core interface tasks
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
	if (typeof params.onlyParamNameRegExp === 'string' && !param.match(new RegExp(params.onlyParamNameRegExp))) {
		return;
	}

	let regexpLiterals = regexpLiteralValidation(params.regexp);

	/*
	 Time between requests, in ms, don't issue all of the payloads at once, that would cause HTTP/503.
	 setDelayInMS() influences sendAndReceive() with a Thread.sleep().
	 NB: JS setTimeout() is not defined for GraalVM (and Oracle Nashorn proved annoying during testing).
	 */
	let timeBetweenRequests = typeof params.timeBetweenRequests === 'number' && params.timeBetweenRequests >= 0
		? params.timeBetweenRequests : 500;
	as.setDelayInMs(timeBetweenRequests);

	for (let i in params.payloads) {
		payload = params.payloads[i];

		// Copy requests before reusing them
		msg = msg.cloneRequest();

		// Do we want to replace or append to the parameter ?
		if (typeof params.appendPayloadToParam === 'boolean' && params.appendPayloadToParam === true) {
			payload = value + payload;
		}

		as.setParam(msg, param, payload);
		as.sendAndReceive(msg, /* followRedirect */ false, /* handleAntiCSRFtoken */ false);

		let searchInText = getSearchInText(msg, params.searchIn);
		let matching = findRegExpInString(searchInText, regexpLiterals);

		if (matching) {
			createAlert(as, msg, params.finding, matching['regexp'] + '\t|\t' + matching['found'])
				.setAttack(payload)
				.setParam(param)
				.raise();
		}

		// Check if the scan was stopped before performing lengthy tasks
		if (as.isStop()) {
			return;
		}
	}
}
