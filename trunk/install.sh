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

PATCHDB=`./.msfpath`/msf3/data/unsploitable/patches.db

sudo cp unsploitable.rb `./.msfpath`/msf3/plugins/
if [ ! -e `./.msfpath`/msf3/data/unsploitable ]; then
	sudo ln -s `pwd` `./.msfpath`/msf3/data/unsploitable 2> /dev/null
fi
