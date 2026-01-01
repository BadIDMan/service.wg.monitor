#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import xbmc
import xbmcgui
import subprocess
import time
import datetime
import os
import re
import sys

# ================= CONFIG =================
WG_IFACE = "wg5"

WG_CONF = f"/storage/.opt/etc/wireguard/{WG_IFACE}.conf"
WG_DIR = "/storage/.opt/etc/wireguard"

ENTWARE_OPKG = "/storage/.opt/bin/opkg"
WG_BIN = "/storage/.opt/bin/wg"
WG_QUICK = "/storage/.opt/bin/wg-quick"
WG_GO = "/storage/.opt/bin/wireguard-go"
JQ_BIN = "/storage/.opt/bin/jq"
CURL_BIN = "/storage/.opt/bin/curl"

LOG = f"/storage/.kodi/temp/{WG_IFACE}-status.log"

CHECK_INTERVAL = 30          # seconds
RETRY_DELAY = 90            # 1,5 minutes
WG_STARTUP_DELAY = 3         # seconds to let interface settle after wg-quick up

PING_TARGET = "8.8.8.8"
# ==========================================

last_state = None
MAX_LOG_LINES = 2000



# ================= LOGGING =================
def log(state, msg):
    global last_state
    if state == last_state:
        return
    last_state = state
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG, "a") as f:
            f.write(f"{ts} [{state}] {msg}\n")
    except Exception:
        pass
    # Removed xbmc.log() to prevent entries in kodi.log

def notify(msg, ms):
    xbmcgui.Dialog().notification(
        "WireGuard Monitor",
        msg,
        xbmcgui.NOTIFICATION_WARNING,
        ms
    )

def run(cmd):
    try:
        return subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True
        ).strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip()
# ==========================================



# ================= LOG TRIM================
def trim_log_file():
    if not os.path.exists(LOG):
        return

    try:
        with open(LOG, "r") as f:
            lines = f.readlines()

        if len(lines) <= MAX_LOG_LINES:
            return

        keep = lines[-MAX_LOG_LINES:]

        with open(LOG, "w") as f:
            f.writelines(keep)

    except Exception:
        pass
# ==========================================



# ================= NETWORK HELPERS =================
def get_default_gateway():
    out = run("ip route show default")
    m = re.search(r"default via ([0-9.]+) dev (\S+)", out)
    if not m:
        return None, None
    return m.group(1), m.group(2)

def lan_link_up(lan_iface):
    gateway, lan_iface = get_default_gateway()
    path = f"/sys/class/net/{lan_iface}/carrier"
    if not os.path.exists(path):
        return False
    try:
        return open(path).read().strip() == "1"
    except Exception:
        return False

def lan_ip():
    gateway, lan_iface = get_default_gateway()
    out = run(f"ip -4 addr show {lan_iface}")
    m = re.search(r"inet ([0-9.]+)/", out)
    return m.group(1) if m else None

def wan_ok():
    gateway, lan_iface = get_default_gateway()
    ip = lan_ip()
    if not ip:
        return False
    out = run(f"curl --interface {lan_iface} -s -m 5 -I https://{PING_TARGET}")
    return "HTTP" in out
# ==========================================


# ================= WIREGUARD HELPERS =================
def wg_exists():
    out = run(f"{WG_BIN} show {WG_IFACE}")
    return "Unable to access interface" not in out

def wg_ip():
    out = run(f"ip -4 addr show {WG_IFACE}")
    m = re.search(r"inet ([0-9.]+)/", out)
    return m.group(1) if m else None

def wg_ping_ok():
    ip = wg_ip()
    if not ip:
        return False
    out = run(f"ping -I {ip} -c 1 -W 3 {PING_TARGET}")
    return "1 received" in out or "0% packet loss" in out

def wg_handshake_ok():
    out = run(f"{WG_BIN} show {WG_IFACE}")
    if "latest handshake" not in out:
        return False
    if "transfer: 0 B received" in out:
        return False
    return True

def wg_up():
    log("WG_MONITOR: ACTION", "Starting WireGuard tunnel")
    notify("Starting WireGuard tunnel...", 5000)
    run(f"{WG_QUICK} up {WG_IFACE}")
    time.sleep(WG_STARTUP_DELAY)  # short stabilization

def wg_down():
    run(f"{WG_QUICK} down {WG_IFACE}")
    time.sleep(WG_STARTUP_DELAY)  # short stabilization
# ==========================================


# ================= VPN INFO =================
def MY_vpn_ip():
    out = run("curl -s -m 5 ifconfig.co")
    if not out:
        return "N/A"
    return out.splitlines()[-1].strip()
# ==========================================


# ================= ENTWARE / WG PROVISIONING =================
def entware_installed():
    return os.path.exists(ENTWARE_OPKG)

def install_entware():
    dlg = xbmcgui.DialogProgress()
    dlg.create(
        "Installing Entware",
        "Entware is being installed.\n\n"
        "Please wait... do NOT reboot or power off."
    )

    run("echo y | /bin/sh /usr/sbin/installentware >/storage/.kodi/temp/entware-install.log 2>&1")

    max_wait = 120
    waited = 0

    while waited < max_wait:
        if os.path.isfile(ENTWARE_OPKG):
            dlg.update(100, "Entware installation completed.")
            time.sleep(1)
            dlg.close()

            xbmcgui.Dialog().ok(
                "Reboot required",
                "Entware installation finished successfully.\n\n"
                "A reboot is required to continue WireGuard setup."
            )

            run("/sbin/reboot")
            sys.exit(0)

        if dlg.iscanceled():
            dlg.close()
            notify("Entware install canceled. Reboot NOT performed", 5000)
            return

        waited += 1
        dlg.update(int((waited / max_wait) * 100))
        time.sleep(1)

    dlg.close()
    xbmcgui.Dialog().ok(
        "Installation timeout",
        "Entware installation did not complete in time.\n"
        "Check storage/.kodi/temp/entware-install.log."
    )

def wg_tools_installed():
    return all(os.path.exists(p) for p in [
        WG_BIN,
        WG_QUICK,
        WG_GO,
        JQ_BIN,
        CURL_BIN
    ])

def install_wg_tools():
    log("WG_MONITOR: ACTION", "Installing WireGuard tools")
    notify("Installing WireGuard tools...", 20000)
    run(f"{ENTWARE_OPKG} update")
    run(
        f"{ENTWARE_OPKG} install "
        "wireguard-tools wireguard-go wg-quick curl jq"
    )

# ================= NORDVPN FETCH =================
def fetch_nordvpn_values():
    cmd = (
        f'{CURL_BIN} -s '
        '"https://api.nordvpn.com/v1/servers/recommendations?'
        '&filters\\[servers_technologies\\]\\[identifier\\]=wireguard_udp&limit=1" '
        f'| {JQ_BIN} -r '
        "'.[]|.hostname, .station, "
        "(.locations|.[]|.country|.city.name), "
        "(.locations|.[]|.country|.name), "
        "(.technologies|.[].metadata|.[].value), .load'"
    )

    out = run(cmd).splitlines()

    if len(out) < 7:
        log("WG_MONITOR: ERROR", "NordVPN API returned no data or insufficient data")
        return None, None, None

    endpoint = out[0]      # line 1
    vpn_ip = out[1]        # line 2
    public_key = out[6]    # line 7

    log("WG_MONITOR: INFO", f"Fetched NordVPN Endpoint={endpoint}, VPN IP={vpn_ip}, Public Key={public_key}")
    return endpoint, vpn_ip, public_key
# ==========================================


# ================= WG CONFIG =================
def create_wg_config():
    gateway, lan_iface = get_default_gateway()
    if not gateway or not lan_iface:
        xbmcgui.Dialog().ok(
            "Network error",
            "Unable to detect default gateway."
        )
        sys.exit(0)

    endpoint, vpn_ip, public_key = fetch_nordvpn_values()
    if not endpoint:
        xbmcgui.Dialog().ok(
            "NordVPN error",
            "Unable to fetch NordVPN WireGuard parameters."
        )
        sys.exit(0)

    os.makedirs(WG_DIR, exist_ok=True)

    template = f"""
# Auto-generated WireGuard template for NordVPN
#
# run:
# curl -s "https://api.nordvpn.com/v1/servers/recommendations?&filters\\[servers_technologies\\]\\[identifier\\]=wireguard_udp&limit=1" | jq -r '.[]|.hostname, .station, (.locations|.[]|.country|.city.name), (.locations|.[]|.country|.name), (.technologies|.[].metadata|.[].value), .load'
#
# output in line 1 is your <endpoint>
# output in line 2 is your <vpn_ip>
# output in line 7 is your <public_key>
#
# run:
# curl -s -u token:<ACCESS_TOKEN> https://api.nordvpn.com/v1/users/services/credentials | jq -r .nordlynx_private_key
# output is your <PRIVATE_KEY>
# <ACCESS_TOKEN> need to be generated in your NordVPN dashboard in Access token section separately for each device you want run Wireguard tunnel on.

[Interface]
Address = 10.5.0.2/32
PrivateKey = <PRIVATE_KEY>
DNS = 103.86.96.100

PreUp = sysctl -w net.ipv6.conf.all.disable_ipv6=1
PostDown = sysctl -w net.ipv6.conf.all.disable_ipv6=0

PreUp = ip route add {vpn_ip}/32 via {gateway} dev {lan_iface}
PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -t nat -A POSTROUTING -o {WG_IFACE} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o {WG_IFACE} -j MASQUERADE; ip route del {vpn_ip}/32 via {gateway} dev {lan_iface}

MTU = 1380

[Peer]
PublicKey = {public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {endpoint}:51820
PersistentKeepalive = 25
"""

    with open(WG_CONF, "w") as f:
        f.write(template)

    os.chmod(WG_CONF, 0o600)

    xbmcgui.Dialog().ok(
        "WireGuard configuration created",
        f"{WG_CONF}   created.\n\nFollow instruction inside this file, then add your Private Key in <PRIVATE_KEY> field and reboot device."
    )

    sys.exit(0)
# ==========================================




# ================= WG CONFIG UPDATE =================
def update_wg_config():
    gateway, lan_iface = get_default_gateway()
    if not gateway or not lan_iface or not wan_ok():
        log("WG_MONITOR: ERROR", "Cannot update wg config – LAN/WAN unavailable")
        return

    endpoint, vpn_ip, public_key = fetch_nordvpn_values()
    if not endpoint or not vpn_ip or not public_key:
        log("WG_MONITOR: ERROR", "Cannot update wg config – NordVPN fetch failed")
        return

    if not os.path.exists(WG_CONF):
        log("WG_MONITOR: ERROR", f"{WG_CONF} does not exist, cannot update")
        return

    try:
        with open(WG_CONF, "r") as f:
            cfg = f.read()

        # 1) Update PublicKey
        cfg = re.sub(
            r"^PublicKey\s*=\s*.+$",
            f"PublicKey = {public_key}",
            cfg,
            flags=re.MULTILINE
        )

        # 2) Update Endpoint
        cfg = re.sub(
            r"^Endpoint\s*=\s*.+$",
            f"Endpoint = {endpoint}:51820",
            cfg,
            flags=re.MULTILINE
        )

        # 3) Update PreUp route add <IP>/32
        cfg = re.sub(
            r"(ip route add )\d{1,3}(?:\.\d{1,3}){3}(/32)",
            rf"\g<1>{vpn_ip}\2",
            cfg
        )

        # 4) Update PostDown route del <IP>/32
        cfg = re.sub(
            r"(ip route del )\d{1,3}(?:\.\d{1,3}){3}(/32)",
            rf"\g<1>{vpn_ip}\2",
            cfg
        )

        with open(WG_CONF, "w") as f:
            f.write(cfg)

        os.chmod(WG_CONF, 0o600)

        log("WG_MONITOR: CONFIG_UPDATE",f"{WG_IFACE}.conf updated (Endpoint, VPN IP, PublicKey refreshed)")
        notify("WireGuard configuration updated with current NordVPN data", 3000)
 
    except Exception as e:
        log("WG_MONITOR: ERROR", f"Failed to update {WG_CONF}: {e}")

# ==========================================


# ================= WG PRIVATE KEY CHECK =================
def get_private_key():
    try:
        with open(WG_CONF, "r") as f:
            for line in f:
                if line.strip().startswith("PrivateKey"):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""

# ==========================================



# ================= MAIN LOOP =================
class WGMonitor(xbmc.Monitor):

    def run(self):
        wg_ok_notified = False
        log("WG_MONITOR: INFO", "WireGuard monitor service starting")
        trim_log_file()

        # --- Provisioning phase ---
        if not entware_installed():
            install_entware()

        if not wg_tools_installed():
            install_wg_tools()
            create_wg_config()

        if not os.path.exists(WG_CONF):
            create_wg_config()

        if os.path.exists(WG_CONF):
            update_wg_config()

        while not self.abortRequested():

            # 1) LAN link check
            gateway, lan_iface = get_default_gateway()
            if not gateway or not lan_iface or not lan_link_up(lan_iface):
                log("WG_MONITOR: LAN_DOWN", "Ethernet cable unplugged")
                notify("Connection to router lost. Check LAN cable/router", 30000)
                last_state = None
                time.sleep(RETRY_DELAY)
                continue

            # 2) PrivateKey validation
            pk = get_private_key()

            # Case 1: Placeholder still present (most common mistake)
            if pk == "<PRIVATE_KEY>":
              log("WG_MONITOR: BAD_PK_01", f"Placeholder <PRIVATE_KEY> still present in {WG_CONF}")
              notify(f"PrivateKey not set in {WG_CONF}. Replace <PRIVATE_KEY> with your NordVPN key", 35000)
              time.sleep(RETRY_DELAY)
              continue

            # Case 2: Missing / empty PrivateKey
            if not pk:
              log("WG_MONITOR: BAD_PK_02", f"PrivateKey missing in {WG_CONF}")
              notify(f"PrivateKey missing in {WG_CONF}. WireGuard tunnel cannot start", 30000)
              time.sleep(RETRY_DELAY)
              continue

            # Case 3: Malformed PrivateKey regex: [A-Za-z0-9+/]{42}[A|E|I|M|Q|U|Y|c|g|k|o|s|w|4|8|0]=$
            if len(pk) != 44 or not re.match(r"^[A-Za-z0-9+/]{42}[A|E|I|M|Q|U|Y|c|g|k|o|s|w|4|8|0]=$", pk):
               log("WG_MONITOR: BAD_PK_03", f"Malformed PrivateKey in {WG_CONF}")
               notify(f"Invalid PrivateKey format in {WG_CONF}. Check and fix", 30000)
               time.sleep(RETRY_DELAY)
               continue

            # 3) Start WireGuard as soon as LAN is up and wg5.conf is valid.
            if not wg_exists():
                wg_up()
                continue

            # 4) WireGuard handshake / crypto check
            if not wg_handshake_ok() or not wg_ping_ok():
                log("WG_MONITOR: WG_BROKEN", "WireGuard keys likely incorrect (no handshake / RX)")
                notify(f"WireGuard tunnel is set but doesn't work. Likely wrong Private/Public key. Check {WG_CONF}", 50000)

                # Show modal dialog with YES / CANCEL option
                user_choice = xbmcgui.Dialog().yesno(
                    "WireGuard Tunnel Broken",
                    "WireGuard tunnel is detected as broken.\n\n"
                    "It might be because your Private Key in your NordVPN account expired or NordVPN rotated their Public Key (but it should be autofixed by restarting device)\n\n"
                    "Check your Private key on Windows with curl and jq:\n"
                    "curl -s -u token:<ACCESS_TOKEN> https://api.nordvpn.com/v1/users/services/credentials | jq -r .nordlynx_private_key\n\n"
                    "<ACCESS_TOKEN> is available in your NordVPN dashboard under Access token section.\n\n"
                    "curl and jq can be installed on Windows machine by launching:\n"
                    "winget install curl and: winget install jq\n\n"
                    "Check NordVPN Public Key at https://nord-configs.selfhoster.nl/ selecting your country.\n\n"
                    "Press [Restart WG] to restart WireGuard tunnel once keys are corrected, or [No VPN] to continue without VPN.",
                    yeslabel="Restart WG",
                    nolabel="No VPN"
                )

                if user_choice:
                    wg_down()
                    wg_up()
                    wg_ok_notified = False
                    notify(f"You decided to restart WireGuard tunnel. It is assumed you made corrections in {WG_CONF} and saved them in the file", 80000)
                    log("WG_MONITOR: INFO_Restart_WG", "User decided to restart the WireGuard tunnel after making a correction in wg5.conf")
                else:
                    wg_down()
                    notify("You decided to run CoreELEC without WireGuard tunnel. It will run this way until device reboot", 50000)
                    log("WG_MONITOR: INFO_EXIT_WG", "User opted to continue without WireGuard tunnel. Service exiting")
                    break  # terminate service loop

                last_state = None
                time.sleep(RETRY_DELAY)
                continue

            # 5) WAN check (bypass WG)
            if not wan_ok():
                log("WG_MONITOR: WAN_DOWN", "Internet unreachable via LAN")
                notify("Internet connection is down. Check router/ISP", 30000)
                last_state = None
                time.sleep(RETRY_DELAY)
                continue

            # 6) All OK
            ip = MY_vpn_ip() if wg_exists() else "N/A"
            log("WG_MONITOR: WG_OK", f"Tunnel active. VPN IP: {ip}")

            if not wg_ok_notified:
                notify(f"WG OK. VPN IP: {ip}", 10000)
                wg_ok_notified = True

            time.sleep(CHECK_INTERVAL)

# ================= MAIN LOOP END =================

if __name__ == "__main__":
    WGMonitor().run()
