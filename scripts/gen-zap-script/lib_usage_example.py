import os

from lib import *


def js_passive_script_example(**zapOptions):
    s = PassiveScript()
    s.params = {
        'finding': Finding(name="Issue Name AAAAAAAAAAAAAAAAAAA", description="Issue Description BBBBBBBBBBBBBBBB",
                           confidence=1, risk=1).__dict__,
        'searchIn': 'response.header',
        'regexp': [
            'X-Frame-Options: DENY'
        ]
    }

    add_and_load_script(s, **zapOptions)


def js_active_script_example(**zapOptions):
    s = ActiveScript()
    s.params = {
        'finding': Finding(name='DDDDDDDDDDDDDDDDDDD', description='Issue description skel', confidence=1, risk=1).__dict__,
        'onlyParamNameRegExp': 'id',
        'payloads': [
            "'",
            '<',
            '%FF',
            '\xfe'
        ],
        'appendPayloadToParam': True,
        'searchIn': 'response.header',
        'regexp': [
            'X-Frame-Options: DENY'
        ]
    }

    add_and_load_script(s, **zapOptions)


zapOptions = {
    'proxies': {k.split('_')[0].lower(): os.environ.get(k) for k in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'] if os.environ.get(k)},
    'apikey': ''
}

delete_all_loaded_scripts(**zapOptions)
js_passive_script_example(**zapOptions)
js_active_script_example(**zapOptions)
