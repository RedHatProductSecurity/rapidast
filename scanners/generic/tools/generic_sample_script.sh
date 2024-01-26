#/bin/sh
# RapiDAST generic scan tool example
# Any script or tool can be used for scanning, but ideally it is recommended to provide results in SARIF for further integration

cat <<DELIM
{
   "runs": [
      {
         "results": [
            {
               "level": "error",
               "locations": [
                  {
                     "physicalLocation": {
                        "artifactLocation": {
                           "uri": "target_artifact"
                        }
                     }
                  }
               ],
               "message": {
                  "text": "A vulnerability FOUND"
               },
               "ruleId": "RAPIDAST00001"
            }
         ],
         "tool": {
            "driver": {
               "name": "rapidast_generic_tool",
               "rules": [
                  {
                     "id": "RAPIDAST00001",
                     "defaultConfiguration": {
                        "level": "error"
                     },
                     "name": "A vulnerability FOUND",
                     "shortDescription": {
                        "text": "A vulnerability FOUND"
                     }
                  }

               ],
               "version": "0.0.1"
            }
         }
      }
   ],
   "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
   "version": "2.1.0"
}

DELIM
