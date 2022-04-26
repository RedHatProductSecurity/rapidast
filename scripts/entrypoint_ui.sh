#!/bin/sh

pip install -r config/requirements.txt
zap.sh -cmd -config api.key=${API_KEY} -config database.newsession=3 -config database.newsessionprompt=false -addoninstall ascanrulesBeta
zap.sh -cmd -addonupdate
zap-webswing.sh
