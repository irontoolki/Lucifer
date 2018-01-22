#!/bin/bash
	sysctl -w net.ipv4.ip_forward=1
	echo "================[ Cleaning  File ]=============="
	echo -e "\\033[48;5;95;38;5;214mStart...\\033[0m"
	DirUP="/var/UP"
	Dirfinal="/var/final"
	Dirdd="/var/dd"
	Dirbb="/var/bb"
	if [ ! -d "$DirUP" ]; then
		mkdir /var/UP
	fi
        if [ ! -d "$Dirfinal" ]; then
                mkdir /var/final
        fi
	if [ ! -d "$Dirdd" ]; then
                mkdir /var/dd
        fi
	if [ ! -d "$Dirbb" ]; then
                mkdir /var/bb
        fi
	chmod 777 /var/UP
	chmod 777 /var/final
	chmod 777 /var/dd
	chmod 777 /var/bb
	export dir=/var/UP
	export dirtmp=/var/bb
	if ls ${Dirbb}/* &>/dev/null
	then
		rm /var/bb/*
	fi
	if ls ${dir}/* &>/dev/null
	then
		cp /var/UP/* /var/bb/
	        if ls ${dirtmp}/* &>/dev/null
		then
			FILES=("/var/bb/"*)
			for filename in "${FILES[@]}"; do
				mystring=$(basename "${filename}")
				IFS=',' read -a fnamearray <<< "$mystring"
				echo "Size of ptr:  ${fnamearray[0]}"
				echo "Orginal src.filename: ${fnamearray[1]}"		
				echo "Temp dst.filename: ${filename}"
				size=$(stat -c %s ${filename})
				ptr=${fnamearray[0]}
				dd bs=$ptr if=${filename} skip=1 seek=0 conv=notrunc of=${filename}  
				dd bs=$((size - $ptr)) if=${filename} skip=1 seek=1 count=0 of=${filename} 
				sed -i 1,2d ${filename}
				sed -i '$d' ${filename}
				dstfilename=$(basename "${filename}")
				echo "Final dst.filename $dstfilename"
				mv  ${filename}  /var/final/${fnamearray[1]}
				echo -e "\\033[48;5;95;38;5;214mNext...\\033[0m"
			done
		fi
	fi
	echo "================[Cleaning File End]=============="

iptables-restore < rule.fw 
