import os

import lib


def js_passive_script_example(**zap_options):
    passive_script = lib.PassiveScript()
    passive_script.params = {
        "finding": lib.Finding(
            name="Issue Name AAAAAAAAAAAAAAAAAAA",
            description="Issue Description BBBBBBBBBBBBBBBB",
            confidence=1,
            risk=1,
        ).__dict__,
        "searchIn": "response.header",
        "regexp": ["X-Frame-Options: DENY"],
    }

    lib.add_and_load_script(passive_script, **zap_options)


def js_active_script_example(**zap_options):
    active_script = lib.ActiveScript()
    active_script.params = {
        "finding": lib.Finding(
            name="DDDDDDDDDDDDDDDDDDD",
            description="Issue description skel",
            confidence=1,
            risk=1,
        ).__dict__,
        "onlyParamNameRegExp": "id",
        "payloads": ["'", "<", "%FF", "\xfe"],
        "appendPayloadToParam": True,
        "searchIn": "response.header",
        "regexp": ["X-Frame-Options: DENY"],
    }

    lib.add_and_load_script(active_script, **zap_options)


ZAP_OPTIONS = {
    "proxies": {
        k.split("_", maxsplit=1)[0].lower(): os.environ.get(k)
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
        if os.environ.get(k)
    },
    "apikey": "",
}

lib.delete_all_loaded_scripts(**ZAP_OPTIONS)
js_passive_script_example(**ZAP_OPTIONS)
js_active_script_example(**ZAP_OPTIONS)
