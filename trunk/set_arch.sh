#!/bin/bash

#	Unmetasploitable - Automatically Patch Metasploitable Vulnerabilities
#	Copyrighted:  Justin M. Wray (wray.justin@gmail.com) & Benjamin Heise
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [[ -z $1 || -z $2  ]]; then
	echo "Usage $0 <IP> <Arch>"
	echo "Example:  $0 192.168.10.10 x86"
	echo "Arch Options Are Based on MSF (x86, x64, etc)"
	exit
fi

MSFDBCONF=`./.msfpath`/config/database.yml
MSFPSQL=`./.msfpath`/postgresql/bin/psql
USERNAME=`sudo grep "username:"  $MSFDBCONF | head -1 | sed -e 's/\s*username:\s*\"//g' -e 's/\"//g'`
export PGPASSWORD=`sudo grep "password:"  $MSFDBCONF | head -1 | sed -e 's/\s*password:\s*\"//g' -e 's/\"//g'`
DATABASE=`sudo grep "database:"  $MSFDBCONF | head -1 | sed -e 's/\s*database:\s*\"//g' -e 's/\"//g'`

echo "UPDATE hosts SET arch = '$2' WHERE address = '$1'" | $MSFPSQL -U $USERNAME $DATABASE
