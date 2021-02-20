#!/usr/bin/bash

# initialize options
auto_secure='false'
show_help='false'
quarantine='false'
set_passwords='false'
lock_firewall='false'
set_interfaces='false'
new_user='false'
validate_checksums='false'
backup_binaries='false'
reset_binaries='false'

# initialize argument variables
new_password=''
target_user=''
new_interface_setting='down'
user=''
port=''

while getopts ':p:ahq:f:i:u:vbB' option; do
  case "$option" in
	'p')
		set_passwords='true'
		new_password=${OPTARG}
		;;
    	'a') 	auto_secure='true';;
    	'h') 	show_help='true';;
    	'q')
		quarantine='true'
		target_user=${OPTARG}
		;;
    	'f') 
		lock_firewall='true'
		port=${OPTARG}
		;;
    	'i') 
		set_interfaces='true'
		new_interface_setting=${OPTARG}
		;;
	'u')
		new_user='true'
		input=($OPTARG)
		user=${input[0]}
		new_password=${input[1]}
		;;
	'v') 	validate_checksums='true';;
	'b') 	backup_binaries='true';;
	'B') 	reset_binaries='true';;
  esac
done

if [ "$reset_binaries" = false ] && [ "$backup_binaries" = false ] && [ "$validate_checksums" = false ] && [ "$new_user" = false ] && [ "$auto_secure" = false ] && [ "$quarantine" = false ] && [ "$set_passwords" = false ] && [ "$lock_firewall" = false ] && [ "$set_interfaces" = false ]; then
	show_help='true'
fi

if [ "$show_help" = true ]; then

    echo ''
    echo 'Options are:'
    echo ''
    echo '    -p set_passwords       Sets every user'\'s' password:  -p newP@ssw0rd'
    echo '    -a auto_secure         Default initial securing of the system'
    echo '    -h show_help           This'
    echo '    -q quarantine          Kills a user'\'s' processes and archives their files in /home'
    echo '    -f lock_firewall       accepts argument "lock" to completely lock down the firewall'
    echo '			     also accepts port number to open a specific port.'
    echo '    -i set_interfaces      quickly sets all interfaces up/down'
    echo '    -u new_user            adds a new user with provided password'
    echo '    -v validate_checksums  Check to make sure checksums of critical files haven'\''t changed'
    echo '    -b backup_binaries     Archives a copy of all binaries in /tmp/bin, sets PATH to use these,'
    echo '                             also creates /tmp/bin.tar.gz and /tmp/bin.enc '\('w/ password you set'\)''
    echo '                             It probably makes sense to obfuscate and hide copies of these.'
    echo '    -B reset_binaries      Removes and replaces /tmp/bin and /tmp/tar.gz with fresh copeis from'
    echo '                             /tmp/bin.enc, if you'\''ve hidden a copy of bin.enc you must move it'
    echo '                             and rename it to /tmp/bin.enc'
    echo
    echo 'Example usages for flags requiring arguments:'
    echo 
    echo '		sudo bash ccdc_linux.sh -p "newpassword"       -- Quotes required w/ space in password'
    echo '		sudo bash ccdc_linux.sh -q username'
    echo '		sudo bash ccdc_linux.sh -i down'
    echo '		sudo bash ccdc_linux.sh -u "username password" -- Quotes required'
    echo '		sudo bash ccdc_linux.sh -f lock		       -- Locks down the firewall'
    echo '		sudo bash ccdc_linux.sh -f 80		       -- Opens port 80'
    
    
fi

# Define colors...
RED=`tput bold && tput setaf 1`
GREEN=`tput bold && tput setaf 2`
YELLOW=`tput bold && tput setaf 3`
BLUE=`tput bold && tput setaf 4`
NC=`tput sgr0`

function RED(){
	echo -e "${RED}${1}${NC}"
}
function GREEN(){
	echo -e "${GREEN}${1}${NC}"
}
function YELLOW(){
	echo -e "${YELLOW}${1}${NC}"
}
function BLUE(){
	echo -e "${BLUE}${1}${NC}"
}

# Testing if root...
if [ $UID -ne 0 ]
then
	RED "You must run this script as root!"
	exit
fi

# auto_secure performs all default actions to lock down the box 
if [ "$auto_secure" = true ]; then

	BLUE "Performing the scripted default actions to secure the system..."

	# Handle ssh
	BLUE "Killing ssh-keygen and removing keys..."
	find / 2>/dev/null -type d | grep /.ssh | xargs rm -rf
	rm -rf $(which ssh-keygen)
	BLUE "Checking if alternate ssh key files have been configured..."
	RED $(grep -rnw /etc/ssh -e AuthorizedKeysFile | grep -v '#')
	echo

	# Check for issues with passwd, shadow, and shell files
	BLUE "Checking for users set up for no password login (missing 'x' in /etc/passwd)... "
	RED $(cat /etc/passwd | cut -d: -f1,2 | grep -v x | cut -d":" -f1) && echo
	BLUE "Listing all user accounts with passwords set, none should be services..."
	RED $(cat /etc/shadow | grep '\$' | cut -d":" -f1) && echo

	# Bring down all network interfaces
	sudo bash ccdc_linux.sh -i down

	# Change all user passwords
	sudo bash ccdc_linux.sh -p "yodagreenears"

	# Create backup accounts
	sudo bash ccdc_linux.sh -u "han spacesmuggler69"
	sudo bash ccdc_linux.sh -u "kylo feistyfella1337"

	# Backup Binaries
	sudo bash ccdc_linux.sh -b 

	# Capture initial checksum of critical files
	sudo bash ccdc_linux.sh -v 

	# Secure firewall then open 22 so we can reconnect
	sudo bash ccdc_linux.sh -f lock
	sudo bash ccdc_linux.sh -f 22

	# Bring interfaces back up
	sudo bash ccdc_linux.sh -i up

	GREEN "Auto-Secure actions complete..."

fi

# set passwords for all users on the system
if [ "$set_passwords" = true ]; then

	BLUE "Setting all user passwords to '$new_password'..."
	for user in $(cat /etc/passwd | cut -d":" -f1)
	do
		echo $user:$new_password | sudo chpasswd
	done
fi

# Move all files owned by a user to their home directory and zip it
if [ "$quarantine" = true ]; then

	BLUE "Killing all of $target_user's processes..."
	pkill -9 -u `id -u $target_user`

	BLUE "Quarantining $target_user's files in /home/$target_user.tgz..."
	BLUE 'making a folder to put the loot in...'
	mkdir /home/$target_user
	chown root:root /home/$target_user
	BLUE 'searching the filesystem for files owned by the user and moving them to the loot folder...'
	find / 2>/dev/null -type f -user $target_user -exec mv '{}' /home/$target_user \;
	find / 2>/dev/null -type d -user $target_user -delete
	BLUE 'archiving the loot folder...'
        tar -czvf /home/$target_user.tgz /home/$target_user
        rm -r /home/$target_user
	GREEN "$target_user has been quarantined.."

fi

# Completely lock down the firewall, this will interrupt all services
if [ "$lock_firewall" = true ]; then

	if [ "$port" = 'lock' ]; then

		# disable firewalld or ufw
		BLUE 'Killing firewalld and ufw so we can manage iptables directly...'
		sudo systemctl stop firewalld 2>/dev/null
		sudo ufw disable 2>/dev/null

		# flush existing rules
		sudo ip6tables -F
		sudo iptables -F
		
		# set default policy to DROP for IPv6
		sudo ip6tables -P INPUT DROP
		sudo ip6tables -P OUTPUT DROP
		sudo ip6tables -P FORWARD DROP

		# set default policy to DROP for IPv4
		sudo iptables -P INPUT DROP
		sudo iptables -P OUTPUT DROP
		sudo iptables -P FORWARD DROP

		# allow connections that our machine requested
		sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

		# allow certain types of icmp
		sudo iptables -A INPUT -m conntrack -p icmp --icmp-type 3 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
		sudo iptables -A INPUT -m conntrack -p icmp --icmp-type 11 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
		sudo iptables -A INPUT -m conntrack -p icmp --icmp-type 12 --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
		
		# allow the loopback mostly for hostname resoulution
		sudo iptables -I INPUT 1 -i lo -j ACCEPT

		GREEN "Firewall locked down, all network traffic will be stopped..."
	fi

	# logic to toggle outgoing traffic
	if [ "$port" = 'out' ]; then
		if [ "$(sudo iptables -L | grep OUTPUT | cut -d" " -f4 | cut -d")" -f1)" = DROP ]; then
			sudo iptables -P OUTPUT ACCEPT
			GREEN "Outgoing traffic permitted..."
		else
			sudo iptables -P OUTPUT DROP
			GREEN "Outgoing traffic denied..."
		fi

	fi

	if [ "$port" != 'lock' ] && [ "$port" != 'out' ]; then

		# ensure valid port number
		if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        		RED "Invalid port number, entry must be an integer, i.e.:"
			RED "	sudo bash ccdc_linux.sh -f 80"
			exit 1
		fi


		# DNS is special because it needs UDP too...
		if [ "$port" = 53 ]; then
			sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
			sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
			sudo iptables -A OUTPUT -p tcp --sport 53 -j ACCEPT
			sudo iptables -A OUTPUT -p udp --sport 53 -j ACCEPT
		fi
		
		# Handle all other ports
		if [ "$port" != 53 ]; then
			sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT
			sudo iptables -A OUTPUT -p tcp --sport $port -j ACCEPT
		fi

		GREEN "Port $port opened..."
	fi
fi

# Set all interfaces either up or down
if [ "$set_interfaces" = true ]; then

	GREEN "Setting all interfaces '$new_interface_setting'"
	for interface in $(ip a | grep mtu | cut -d":" -f2)
	do
		sudo ip link set $interface $new_interface_setting
	done
fi

# Create a user with a password
if [ "$new_user" = true ]; then
	
	BLUE "Created user: '$user' with password: '$new_password'..."
	sudo useradd $user
	sudo usermod -aG wheel $user 2>/dev/null
	sudo usermod -aG sudo $user 2>/dev/null
	sudo usermod -aG root $user 2>/dev/null
	echo $user:$new_password | sudo chpasswd
fi

# Get the checksums for a list of files, compare to known hashes, alert user of differences
if [ "$validate_checksums" = true ]; then

	if test -f /var/rechk; then
		BLUE "Comparing current checksums of critical files to those previously obtained..."
	else
		BLUE "Capturing initial checksums of critical files..."
	fi
	BLUE "The reference checksums are always stored at /var/rechk"

	# add critical files or directories to be checked here using absolute paths
	# wrapped in quotes and separated by a single space
	declare -a critical_items=("/bin" "/dev" "/etc" "/home" "/media" "/mnt" "/opt" "/root" "/sbin" "/tmp" "/var/www")
	for item in "${critical_items[@]}"; 
	do
		for file in $(sudo find $item 2>/dev/null -type f)
		do
			temp_string="$file : $(cat $file | md5sum)"
			echo $temp_string >> current_checksums
		done
	done
	if test -f /var/rechk; then
		BLUE "Checking for differences..."
		openssl enc -d -aes-256-cbc -in /var/rechk -out /var/rechk.tmp 2>/dev/null
		echo
		diff -qs /var/rechk.tmp current_checksums
		diff -y --suppress-common-lines /var/rechk.tmp current_checksums > diff.tmp
		echo
		RED "Files added..." 
		cat diff.tmp | grep \> | sed -e 's/^[[:space:]]*//'  | cut -f2 | cut -d":" -f1
	       	echo
		RED "Files deleted..." 
		cat diff.tmp | grep \< | cut -d":" -f1 && echo
		RED "Files changed..."
		cat diff.tmp | grep \| | cut -d":" -f1 && echo
		echo
		rm current_checksums
		openssl enc -e -aes-256-cbc -in /var/rechk.tmp -out /var/rechk 2>/dev/null
	   	rm /var/rechk.tmp	
	else
		openssl enc -e -aes-256-cbc -in current_checksums -out /var/rechk 2>/dev/null
		rm current_checksums
		GREEN "Successfully stashed the reference checksums in /var/rechk"
	fi
fi

if [ "$backup_binaries" = true ]; then
	BLUE "Backing up binaries..." 
	BLUE "This could take a minute or so..."
	sudo mkdir /tmp/bin
	IFS=:
	for directory in $PATH;
	do
		sudo cp -r $directory/* /tmp/bin 2>/dev/null
	done
	
	tar czf /tmp/bin.tar.gz /tmp/bin
	openssl enc -e -aes-256-cbc -in /tmp/bin.tar.gz -out /tmp/bin.enc 
	GREEN 'Take a note of the following md5 checksum for bin.enc...'
	md5sum /tmp/bin.enc
fi

if [ "$reset_binaries" = true ]; then
	BLUE "Resetting binaries from backup..."
	if test ! -f /tmp/bin.enc; then
		RED 'No backup binaries found...'
		RED 'This script looks for /tmp/bin.enc'
		RED 'Put the backup file there.'
		exit 1
	fi
	
	sudo rm -f /tmp/bin/* /tmp/bin.tar.gz
	openssl enc -d -aes-256-cbc -in /tmp/bin.enc -out /tmp/bin.tar.gz
	tar xzf /tmp/bin.tar.gz -C /
fi
