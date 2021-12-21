/*
 * Shared functions.
 */

/*
 * Extracts the body or header string from a HttpMessage.
 *
 * @param msg HttpMessage being processed
 * @param searchIn str formatted as such '{request,response}.{body,header}'
 * @returns The request/response body or header as a string.
 */
function getSearchInText(msg, searchIn) {
	let searchInMethod = 'get' + searchIn.split('.').map(str => str.charAt(0).toUpperCase() + str.slice(1)).join('');
	let func = msg[searchInMethod];

	return typeof func === typeof Function ? func().toString() : null;
}

/*
 * Ensure the array of regexp literals contains only valid regexp
 *
 * @param regexpLiterals Array of regexp strings.
 * @param doThrow Throw on error, default is print only.
 * @returns The filtered array of valid regexp literals.
 */
function regexpLiteralValidation(regexpLiterals, doThrow=false) {
	let acc = [];
	for (let i in regexpLiterals) {
		try {
			new RegExp(regexpLiterals[i], '');
			acc.push(regexpLiterals[i]);

		} catch (e) {
			msg = `Discarding invalid regexp "${regexpLiterals[i]}" with error: ${e}`;
			if (doThrow) {
				throw msg;
			} else {
				print(msg);
			}
		}
	}

	return acc;
}

/*
 * Applies a collection of regexp strings to msg. Only the first match is reported.
 *
 * @param str Text for the regexp to match.
 * @param regexpLiterals Array of regexp strings.
 * @param regexOptions Options to match the regexps with.
 * @returns An object with the matching regexp and first extracted group if found, null otherwise.
 */
function findRegExpInString(str, regexpLiterals, regexpOptions = '') {
	let res = null;

	if (str !== null && typeof str === 'string') {
		for (let i in regexpLiterals) {
			let found = str.match(new RegExp(regexpLiterals[i], regexpOptions));

			if (found) {
				res = {'regexp': regexpLiterals[i], 'found': found[0]};
				break;
			}
		}
	}

	return res;
}

/*
 * Alert builder helper.
 * @param scanner Active/passive scanner ('as' or 'ps' arguments of 'scan()').
 * @param msg HttpMessage to report the alert for.
 * @param finding 'param.finding' object.
 * @param evidence String highlighting why it's an issue.
 * @returns An alert object (not raised).
 */
function createAlert(scanner, msg, finding, evidence) {
	return scanner.newAlert()
		.setName(finding.name)
		.setDescription(finding.description)
		.setRisk(finding.risk)
		.setConfidence(finding.confidence)
		.setUri(msg.getRequestHeader().getURI().toString())
		.setEvidence(evidence)
		.setMessage(msg);
}

/*
 * End of shared functions.
 */