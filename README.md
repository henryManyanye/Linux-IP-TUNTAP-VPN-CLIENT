sudo route add -net 0.0.0.0 netmask 0.0.0.0 gw 10.0.0.3 dev tun22 

OR 

sudo route add -net 0.0.0.0 netmask 0.0.0.0 dev tun22

ALSO, change (if i don't, dns resolution will fail on browsers and other cmd programs that resolve dns names) nameserver part of /etc/resolv.conf to: 
	nameserver 8.8.4.4

OR, choose any other nameserver that i like.

#include <linux/if.h> WILL FAIL ON MY DESKTOP. I DON'T KNOW WHY IT WORKS ON MY LAPTOP.
