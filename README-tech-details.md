Before using this service, a NordVPN user must generate a WireGuard Private Key.

To do this, log in to: https://my.nordaccount.com/dashboard/nordvpn/

In the Access Token section, create a token.
After creating the token, the corresponding WireGuard Private Key must be retrieved.

Command to run to retrieve WireGuard NordVPN Private Key:

`curl -s -u token:<ACCESS_TOKEN> https://api.nordvpn.com/v1/users/services/credentials | jq -r .nordlynx_private_key`


To run these commands on Windows, curl and jq must be installed.
They can be installed easily using:

`winget install curl`
`winget install jq`
