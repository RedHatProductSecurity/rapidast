/*
 * This script is intended to be used along with authentication/OfflineTokenRefresher.js to
 * handle an OAUTH2 offline token refresh workflow.
 *
 * authentication/OfflineTokenRefresher.js will automatically fetch the new access token for every unauthorized
 * request determined by the "Logged Out" or "Logged In" indicator previously set in Context -> Authentication.
 *
 *  httpsender/AddBearerTokenHeader.js will add the new access token to all requests in scope
 * made by ZAP (except the authentication ones) as an "Authorization: Bearer [access_token]" HTTP Header.
 *
 * @author Laura Pardo <lpardo at redhat.com>
 */

var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

function logger() {
    //print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

function sendingRequest(msg, initiator, helper) {
    logger("{sendingRequest}: called");
    // add Authorization header (when it exists) to all request in scope except the authorization request itself
    var bearer = ScriptVars.getGlobalVar("access_token");
    if (initiator !== HttpSender.AUTHENTICATION_INITIATOR && msg.isInScope() && bearer ) {
        logger("{sendingRequest}: Adding bearer to Authorization header");
        msg.getRequestHeader().setHeader("Authorization", "Bearer " + bearer);
    }

    return msg;
}

function responseReceived(msg, initiator, helper) {}
