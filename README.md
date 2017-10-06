modbus-vcr
==========

# About

This is a simple plugin for Ettercap which exploits the lack of data integrity
in control systems protocols.

This Ettercap plugin performs a MITM attack against Modbus systems.  It records
modbus communication for ten seconds, and then overwrites future status data
on a control system network with previously-recorded responses.  This
effectively blinds a control system operator to the status of their process,
while leading the operator to believe that status updates are still occuring.

It is meant to demonstrate a decades-old issue with process control systems
that has never been addressed by vendors nor by operators.  My hope is that
this will increase public dialogue about replacing control systems protocols
which lack data integrity, especially in critical infrastructure.
# Compilation
To compile this plugin, you will want to check out the current version of
ettercap from git (it contains patches necessary for this plugin to work),
place the modbus_vcr.c file into the ettercap plugins directory, and modify
the plugins configuration file so that building ettercap will also build
the plugin.

To build ettercap on a modern Linux attack distro (such as Kali 2017.1), install cmake libncurses5-dev libgtk2.0-dev libssl-dev curl libidn11-dev librtmp-dev libpcap-dev bison libcurl3 libcurl4-openssl-dev libnet1-dev 

Comment out all calls to sslw_dissect_add() in src/dissectors
Comment out all calls to sslw_dissect_move() 
Comment out all calls to sslw* functions in src/


# Disclaimer

Please use this tool for demonstration purposes only, and only on non-critical
systems.
