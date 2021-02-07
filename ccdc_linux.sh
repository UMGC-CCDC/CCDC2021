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

while getopts ':p:ahq:fi:u:vbB' option; do
  case "$option" in
	'p')
	    set_passwords='true'
	    new_password=${OPTARG}
	    ;;
    	'a') auto_secure='true';;
    	'h') show_help='true';;
    	'q')
	    quarantine='true'
	    target_user=${OPTARG}
	    ;;
    	'f') lock_firewall='true';;
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
	'v') validate_checksums='true';;
	'b') backup_binaries='true';;
	'B') reset_binaries='true';;
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
    echo '    -f lock_firewall       completely locks down the firewall, all services will be affected'
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
    
    
fi

# Define colors...
RED=`tput bold && tput setaf 1`
GREEN=`tput bold && tput setaf 2`
YELLOW=`tput bold && tput setaf 3`
BLUE=`tput bold && tput setaf 4`
NC=`tput sgr0`

function RED(){
	echo -e "\n${RED}${1}${NC}"
}
function GREEN(){
	echo -e "\n${GREEN}${1}${NC}"
}
function YELLOW(){
	echo -e "\n${YELLOW}${1}${NC}"
}
function BLUE(){
	echo -e "\n${BLUE}${1}${NC}"
}

# Testing if root...
if [ $UID -ne 0 ]
then
	RED "You must run this script as root!" && echo
	exit
fi

# auto_secure performs all default actions to lock down the box 
if [ "$auto_secure" = true ]; then

	BLUE "Performing the scripted default actions to secure the system..."
	
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

	# Leave the user looking at /etc/passwd
	ip addr
	sudo cat /etc/passwd
	GREEN "Auto-Secure actions complete..."
	GREEN "A good next step would be to identify/remove suspicous or unused users..."

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

	BLUE "Quarantining $target_user's files in /home/$target_user.tgz..." && echo
	echo 'making a folder to put the loot in...'
	mkdir /home/$target_user
	chown root:root /home/$target_user
	echo 'searching the filesystem for files owned by the user and moving them to the loot folder...'
	find / 2>/dev/null -type f -user $target_user -exec mv '{}' /home/$target_user \;
	find / 2>/dev/null -type d -user $target_user -delete
	echo 'archiving the loot folder...'
        tar -czvf /home/$target_user.tgz /home/$target_user
	echo 'removing the unarchived loot folder...'
        rm -r /home/$target_user

fi

# Completely lock down the firewall, this will interrupt all services
if [ "$lock_firewall" = true ]; then

	BLUE "Firewall locked down, all network traffic will be stopped..."
	iptables -F
	iptables -P INPUT DROP
	iptables -P OUTPUT DROP
	iptables -P FORWARD DROP
fi

# Set all interfaces either up or down
if [ "$set_interfaces" = true ]; then

	BLUE "Setting all interfaces '$new_interface_setting'"
	for interface in $(ip a | grep mtu | cut -d":" -f2)
	do
		sudo ip link set $interface $new_interface_setting
	done
fi

# Create a user with a password
if [ "$new_user" = true ]; then
	
	BLUE "Created user: '$user' with password: '$new_password'..."
	sudo useradd $user
	sudo usermod -aG wheel $user
	sudo usermod -aG sudo $user
	sudo usermod -aG root $user
	echo $user:$new_password | sudo chpasswd
fi

# Get the checksums for a list of files, compare to known hashes, alert user of differences
if [ "$validate_checksums" = true ]; then

	if test -f /root/reference_checksums; then
		BLUE "Comparing current checksums of critical files to those previously obtained..."
	else
		BLUE "Capturing initial checksums of critical files..."
	fi
	echo
	BLUE "The reference checksums are always stored at /root/reference_checksums" && echo

	# add critical files or directories to be checked here using absolute paths
	# wrapped in quotes and separated by a single space
	declare -a critical_items=("/etc" "/tmp/bin" "/bin" "/sbin")
	for item in "${critical_items[@]}"; 
	do
		for file in $(sudo find $item -type f)
		do
			temp_string="$file : $(cat $file | md5sum)"
			echo $temp_string >> current_checksums
		done
	done
	if test -f /root/reference_checksums; then
		RED "Checking for differences..." && echo
		diff -qs /root/reference_checksums current_checksums
		diff -y --suppress-common-lines /root/reference_checksums current_checksums
		rm current_checksums
	else
		mv current_checksums /root/reference_checksums
		GREEN "Successfully stashed the reference checksums in /root/reference_checksums" && echo
	fi
fi

if [ "$backup_binaries" = true ]; then
	BLUE "Backing up binaries..." 
	BLUE "This could take a minute or so..." && echo
	sudo mkdir /tmp/bin
	IFS=:
	for directory in $PATH;
	do
		sudo cp -r $directory/* /tmp/bin
	done
	
	tar czf /tmp/bin.tar.gz /tmp/bin
	openssl enc -e -aes-256-cbc -in /tmp/bin.tar.gz -out /tmp/bin.enc 
	GREEN 'Take a note of the following md5 checksum for bin.enc...'
	md5sum /tmp/bin.enc
fi

if [ "$reset_binaries" = true ]; then
	BLUE "Resetting binaries from backup..." && echo
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
