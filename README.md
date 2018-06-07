An IP Firewall written in Python.

Our second year architecture end year project.

Requirements

- You must have python 3.5 installed on your computer.
- A Linux system.

Setting Up

sudo apt-get install build-essential python-dev libnetfilter-queue-dev

cd Firewall/
source venv/bin/activate (Now virtual environnement should be enabled)

Usage

Sniff network traffic:
sudo venv/bin/python3.5 firewall.py --sniff

Read capture file:
sudo venv/bin/python3.5 firewall.py --file myfile.cap

You can filter network incoming packets based on rules in "rules.rl":
sudo venv/bin/python3.5 firewall.py --run

Here's how you can define firewall rules:

Open "rules.rl" with your text editor:

<ip_source>;<action>

Example:

192.168.1.45;DROP
192.168.1.78;ACCEPT
other rules...

You can also add a new rule by typing "sudo venv/bin/python3.5 firewall.py --add"

-> This rule drops incoming packets from ip source 192.168.1.45 and accepts those from 192.168.1.78.

Test this Firewall

Assume next commands with you config:

Client IP: 192.168.1.45
Firewall Computer IP: 192.168.1.79

Assume we want to block the previous client ip from incoming requests:
Edit "rules.rl" and add:

192.168.1.45;BLOCK

Now, launch the firewall, so it will consider our rule:
sudo venv/bin/python3.5 firewall.py --run

Now, for test, perform ICMP requests to the firewall computer:
ping 192.168.1.79

You should get any response since our firewall blocks that requests.

If you stop the firewall, you'll realize that ICMP requests work now.

