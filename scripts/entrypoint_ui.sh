#!/bin/sh

pip install -r requirements.txt
zap.sh -cmd -config api.key=${API_KEY} -config database.newsession=3 -config database.newsessionprompt=false -addoninstall ascanrulesBeta
zap.sh -cmd -addonupdate
zap-webswing.sh
