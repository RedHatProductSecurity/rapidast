#!/bin/sh

pip install -r config/requirements.txt
zap.sh -cmd -addoninstall ascanrulesBeta
zap.sh -cmd -addonupdate
zap.sh -daemon -port 8090 -config api.key=${API_KEY}
