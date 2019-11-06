#!/bin/bash

IFACE_NAME=""

ifconfig wlxc025e911c837 down
iwconfig wlxc025e911c837 mode monitor
ifconfig wlxc025e911c837 up
