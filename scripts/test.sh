sh -c env -i PATH=/usr/bin:/usr/local/bin:/usr/sbin run-parts --lsbsysinit /etc/update-motd.d > foo.d
sh -c "if [ ! -x /usr/lib/notification-daemon/notification-daemon ] || [ "$GDMSESSION" = guest-restricted ] || [ "$GDMSESSION" = gnome-classic-guest-restricted ] [ "$GDMSESSION" = default -a "$(basename `readlink /etc/alternatives/x-session-manager`)" = gnome-session ] || [ "$GDMSESSION" = ubuntu ] || [ "$GDMSESSION" = ubuntu-2d ]; then exec /usr/lib/notify-osd/notify-osd; else exec /usr/lib/notification-daemon/notification-daemon; fi"


