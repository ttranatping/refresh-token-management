tenant=tenant2

# 1 - Register client
newman run tokenmgt.postman_collection.json --ssl-client-cert-list ssl-client-cert-list.json --ignore-redirects --insecure --folder "1 - Register client" --export-environment current.env --env-var tenant=${tenant}

# 2 - Authenticate and get first access_token
newman run tokenmgt.postman_collection.json --ssl-client-cert-list ssl-client-cert-list.json --ignore-redirects --insecure --folder "2 - Authenticate and get first access_token" --export-environment current.env --environment current.env --env-var tenant=${tenant} --env-var username=crn0
newman run tokenmgt.postman_collection.json --ssl-client-cert-list ssl-client-cert-list.json --ignore-redirects --insecure --folder "2 - Authenticate and get first access_token" --export-environment current.env --environment current.env --env-var tenant=${tenant} --env-var username=crn1
newman run tokenmgt.postman_collection.json --ssl-client-cert-list ssl-client-cert-list.json --ignore-redirects --insecure --folder "2 - Authenticate and get first access_token" --export-environment current.env --environment current.env --env-var tenant=${tenant} --env-var username=crn2
newman run tokenmgt.postman_collection.json --ssl-client-cert-list ssl-client-cert-list.json --ignore-redirects --insecure --folder "2 - Authenticate and get first access_token" --export-environment current.env --environment current.env --env-var tenant=${tenant} --env-var username=crn3
newman run tokenmgt.postman_collection.json --ssl-client-cert-list ssl-client-cert-list.json --ignore-redirects --insecure --folder "2 - Authenticate and get first access_token" --export-environment current.env --environment current.env --env-var tenant=${tenant} --env-var username=crn4

# 3 - Retrieve latest access_token then call API
newman run tokenmgt.postman_collection.json --ssl-client-cert-list ssl-client-cert-list.json --ignore-redirects --insecure --folder "3 - Retrieve latest access_token then call API" --export-environment current.env --environment current.env --env-var tenant=${tenant}
