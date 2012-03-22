#!/bin/bash

#	Unsploitable - Automatically Patch Metasploitable Vulnerabilities
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

if [ -e .updatelists ]; then
	wget -nc -c -i .updatelists -P .updateslist --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.7 (KHTML, like Gecko) Ubuntu/11.10 Chromium/16.0.912.77 Chrome/16.0.912.77 Safari/535.7" --referer="http://www.windowsupdatesdownloader.com/"
	zcat .updateslist/* | grep "<url>" | sed -e 's/<url>//g' -e 's/<\/url>//g' -e 's/^\s*//g' -e 's/\s*$//g' | sort -u > .updates
	wget -nc -c -i .updates -P patches
fi
