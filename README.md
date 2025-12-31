This is a python code that create service which will run in CoreELEC-like devices with Kodi which allows setting up and managing a WireGuard tunnel for NordVPN only.

It automatically installs Entware and the required tools: wireguard-tools, wireguard-go, wg-quick, curl, and jq.

Before using this service, a NordVPN user must generate a WireGuard Private Key.
To do this, log in to: https://my.nordaccount.com/dashboard/nordvpn/

In the Access Token section, create a token.
After creating the token, the corresponding WireGuard Private Key(s) must be retrieved.

The full process is explained in this YouTube video:
https://youtu.be/eY4sYGYt0b4?si=GMt0W4KKJtFXS6zG

The commands needed to retrieve and use the keys are available here:
https://github.com/automation-avenue/NordVPN_Wireguard_key/blob/main/README.md

To run these commands on Windows, curl and jq must be installed.
They can be installed easily using:

winget install curl
winget install jq

Command to run to get WireGuard NordVPN Private Key is:
curl -s -u token:<ACCESS_TOKEN> https://api.nordvpn.com/v1/users/services/credentials | jq -r .nordlynx_private_key

Once the setup is complete, this service monitors the WireGuard tunnel status, automatically restarts it if it goes down, and displays notifications in Kodi.

I am not a Python programmer.
This service was created with the help of ChatGPT.

I tested this service in many usage scenarios, but it may not work correctly in every environment.
Everyone is free to modify and adapt this service for their own needs.
I am not responsible for any issues or consequences that may occur while using it.
