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

	#######################################################################################################
	#  PORTIONS OF THE CODEBASE ARE DERIVED FROM auto_exploit.rb A METASPLOIT MODULE BY Carlos Perez      #
	#	Cases of derived or copied code will be annotated					      #
	#######################################################################################################
	# Copyright (c) 2012, Carlos Perez <carlos_perez[at]darkoperator.com
	# All rights reserved.
	#
	# Redistribution and use in source and binary forms, with or without modification, are permitted
	# provided that the following conditions are met:
	#
	# Redistributions of source code must retain the above copyright notice, this list of conditions and
	# the following disclaimer.
	#
	# Redistributions in binary form must reproduce the above copyright notice, this list of conditions
	# and the following disclaimer in the documentation and/or other materials provided with the
	# distribution.
	#
	# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
	# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
	# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
	# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
	# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
	# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
	# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	#######################################################################################################

module Msf

	class Plugin::Unsploitable < Msf::Plugin

		class Unsploitable
			include Msf::Ui::Console::CommandDispatcher

			def name
				"unsploitable"
			end

			# Define Commands
			def commands
				{
					"unsploit_patch"    => "Build Missing Patches (based on vulnerabilities).",
					"unsploit_show" => "Show Matched Patches (based on vulnerabilities)."
				}
			end

			#######################################################################################################
			#  BEGIN DERIVED CODE FROM auto_exploit.rb BY Carlos Perez - COPYRIGHT NOTICE AT TOP OF FILE          #
			#######################################################################################################
			# Normalize Operating System Names
			def normalise_os(os_name)
				case os_name
				when /(Microsoft|Windows)/i
					os = "windows"
				when /(Linux|Ubuntu|CentOS|RedHat)/i
					os = "linux"
				when /aix/i
					os = "aix"
				when /(freebsd)/i
					os = "bsd"
				when /(hpux|hp-ux)/i
					os = "hpux"
				when /solaris/i
					os = "solaris"
				when /(Apple|OSX|OS X)/i
					os = "osx"
				end
				return os
			end
			# Parse the CVE, BID and OSVDB Values For Matching
			def parse_references(refs)
				references = []
				refs.each do |r|
					# Remove URL References 
					next if r.ctx_id == "URL"
					# Format the Reference in Nessus Format
					references << "#{r.ctx_id}-#{r.ctx_val}"
				end
				return references
			end

			# Build Matching Exploits to Patches
			def build_matches(range)
				# Variables
				filter = []
				exploits =[]
				matched_exploits = []
				missing_patches = []
				basedir = Msf::Config.install_root + "/data/unsploitable/"

				# Verify Vulnerabilities Are Loaded
				if framework.db.workspace.vulns.length == 0
					print_error("Error:  No Vulnerabilities in Database - Please Load Vulnerability Scan")
					return
				end

				# Build Filer of Hosts to Exclude
				range.each do |r|
					Rex::Socket::RangeWalker.new(r).each do |i|
						filter << i
					end
				end

				#  Build Index of Exploits in MSF
				print_status("Loading Exploit Index for Matching...")
				framework.exploits.each_module do |n,e|
					exploit = {}
					x=e.new
					if x.datastore.include?('RPORT')
						exploit = {
							:exploit => x.fullname,
							:port => x.datastore['RPORT'],
							:platforms => x.platform.names.join(" "),
							:date => x.disclosure_date,
							:references => x.references,
							:rank => x.rank
						}
						exploits << exploit
					end
				end

				#  Match Exploits
				print_status("Building List of Matched Exploits...")
				framework.db.workspace.hosts.each do |h|
					# Verify We Have Vulnerabilities for this System
					if h.vulns.length > 0
						os_type = normalise_os(h.os_name)
						exploits.each do |e|
							found = false
							if e[:platforms].downcase =~ /#{os_type}/ or e[:platforms].downcase == "" or e[:platforms].downcase =~ /php/i
								# Parse Exploit Reference
								e_refs = parse_references(e[:references])
								h.vulns.each do |v|
									v.refs.each do |f|
										# Filter Out Nessus Informational Findings
										next if f.name =~ /^NSS|^CWE/
										if e_refs.include?(f.name) and not found
											# Skip Filtered Hosts
											next if filter.include?(h.address)
											# Save Relevant Exploit Information
											exploit = {
												:exploit => e[:exploit],
												:port => e[:port],
												:target => h.address,
												:osver => h.os_name + " " + h.os_flavor,
												:ospatch => h.os_sp,
												:ostype => os_type,
												:hostarch => h.arch,
												:rank => e[:rank]
											}
											matched_exploits << exploit
											found = true
										end
									end
								end
							end
						end
					end

				end

				#######################################################################################################
				#  END DERIVED CODE										      #
				#######################################################################################################

				print_status("Building List of Matched Patches...")
				if matched_exploits.length > 0
					matched_exploits.each do |e|

						# Match Patches to Exploit
						custom_patches = open(basedir + 'custom.db').grep(/(#{e[:exploit]}|^\|)/)
						provided_patches = open(basedir + 'patches.db').grep(/(#{e[:exploit]}|^\|)/)
						patches = custom_patches | provided_patches

						# Variables
						final = false
						kb = nil
						cve = nil
						mssb = nil

						# Filter Through Patches
						patches.each do |patch|
							patch.chomp!
							elements = patch.split("|")

							# Verify OS Version
							unless elements[1].nil? || elements[1] == 0 || elements[1].length == 0
								if (e[:osver] =~ /#{elements[1]}/i)
						                        final = true
						                else
						                        final = false
						                        next
						                end
						        else
						                final = true
						        end

							# Verify OS Patch Level/SP
							unless elements[2].nil? || elements[2] == 0 || elements[2].length == 0
								if (e[:ospatch] =~ /#{elements[2]}/i)
									final = true
								else
									final = false
									next
								end
							else
								final = true
							end

							# Verify Architecture
							unless elements[3].nil? || elements[3] == 0 || elements[3].length == 0
						                if (e[:hostarch] =~ /#{elements[3]}/i)
						                        final = true
						                else
									final = false
						                        next
								end
						        else
						                final = true
						        end

							# Parse Patch Information
							if final
								final = elements[4]
								unless elements[5].nil?
									kb = "KB: " + elements[5]
								else
									kb = nil
								end
								unless elements[6].nil?
									cve = "CVE: " + elements[6]
								else
									cve = nil
								end
								unless elements[7].nil?
									mssb = "MSSB: " + elements[7]
								else
									mssb = nil
								end
								break
							end

						end

						if final
				                        prereq_file = false
							prereq_cmd = false
				                        prereqs = open(basedir + 'prereq.db').grep(/\|/)
				                        prereqs.each do |line|
								line.chomp!
								elements = line.split("|")
								if (e[:osver] =~ /#{elements[0]}/i) && (e[:hostarch] =~ /#{elements[1]}/i)
									prereq_file = elements[2]
									prereq_cmd = elements[3]
									break
								end
							end
							missing_patch = {
								:exploit => e[:exploit],
								:target => e[:target],
								:ostype => e[:ostype],
								:patchfile => final,
								:kb => kb,
								:cve => cve,
								:mssb => mssb,
								:prereq_file => prereq_file,
								:prereq_cmd => prereq_cmd
							}
							missing_patches << missing_patch
							print_good("#{e[:target]} Missing Patch: #{final} (#{e[:exploit]} #{kb} #{cve} #{mssb})")
						end					
					end
				else
					print_status("No Matching Exploits Found.")
				end

				return missing_patches
			end

			def cmd_unsploit_patch(*args)
				# Define Options
				opts = Rex::Parser::Arguments.new(
					"-b"   => [ false, "Generate a Batch file instead of the default VBScript"],
					"-f"   => [ true, "Comma Separated List of IP's and Ranges to Exclude"],
					"-h"   => [ false, "Command Help"],
					"-s"   => [ true, "Server Where Patches Are Located (HTTP/HTTPS/FTP)"]
				)

				# Variables
				patchsrv = nil
				range = []
				batch_file = false
				missing_patches = []
				basedir = Msf::Config.install_root + "/data/unsploitable/"
				timestamp = Time.now.to_i

				# Parse options
				opts.parse(args) do |opt, idx, val|
					case opt
						when "-s"
							patchsrv = val
						when "-f"
		                                	range = val.gsub(" ","").split(",")
						when "-b"
							batch_file = true
						when "-h"
							print_line(opts.usage)
							return
					end
				end

				# Check Server Information
				if patchsrv.nil? || patchsrv == 0 || patchsrv.length == 0
					print_error("Error:  You Must Specify HTTP/HTTPS/FTP Location of Patches")
					return
				end

				missing_patches = build_matches(range)

				print_status("Building Patch Script...")
				patching_targets = []
				if missing_patches.length > 0
					# Sort by rank with highest ranked exploits first
					missing_patches.sort! { |x, y| y[:kb] <=> x[:kb] }

					# Get List of Patch Targets
					missing_patches.each do |mp|
						patching_targets << mp[:target]
					end
					patching_targets = patching_targets.uniq

					# Start Building Patch Scripts
					missing_patches.each do |mp|
						if (mp[:ostype] =~ /win/i)
							if batch_file
								ext = "bat"
							else
								ext = "vbs"
							end
							File.open(mp[:target] + "_unsploitable_patcher.#{ext}", 'a') do |file|
								if (mp[:prereq_file] && mp[:prereq_cmd])
									if (mp[:prereq_file] =~ /^(ht|f)tp[s]*\:/)
										prereqloc = mp[:prereq_file]
										prereq_parts = mp[:prereq_file].split("/")
										prereqfile = prereq_parts.pop
									else
										prereqloc = patchsrv + mp[:prereq_file]
										prereqfile = mp[:prereq_file]
									end
									if batch_file
										file.puts("curl -O #{prereqloc}")
										file.puts("#{prereqfile} #{mp[:prereq_cmd]}")
									else
										file.puts("strFileURL = \"#{prereqloc}\"")
										file.puts("strHDLocation = \"#{prereqfile}\"")
										file.puts("Set objXMLHTTP = CreateObject(\"MSXML2.XMLHTTP\")")
										file.puts("objXMLHTTP.open \"GET\", strFileURL, false")
										file.puts("objXMLHTTP.send()")
										file.puts("If objXMLHTTP.Status = 200 Then")
										file.puts("Set objADOStream = CreateObject(\"ADODB.Stream\")")
										file.puts("objADOStream.Open")
										file.puts("objADOStream.Type = 1")
										file.puts("objADOStream.Write objXMLHTTP.ResponseBody")
										file.puts("objADOStream.Position = 0")
										file.puts("Set objFSO = Createobject(\"Scripting.FileSystemObject\")")
										file.puts("If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation")
										file.puts("Set objFSO = Nothing")
										file.puts("objADOStream.SaveToFile strHDLocation")
										file.puts("objADOStream.Close")
										file.puts("Set objADOStream = Nothing")
										file.puts("End if")
										file.puts("Set objXMLHTTP = Nothing")
										file.puts("Set filesys = CreateObject(\"Scripting.FileSystemObject\")")
										file.puts("Set filetxt = filesys.OpenTextFile(\"patcher.bat\", 8, True)")
										file.puts("filetxt.WriteLine(\"#{prereqfile} #{mp[:prereq_cmd]}\")")
										file.puts("filetxt.Close")
									end
								end
								if (mp[:patchfile] =~ /^(ht|f)tp[s]*\:/)
									patchloc = mp[:patchfile]
									patchfile_parts = mp[:patchfile].split("/")
									patchfile = patchfile_parts.pop
								else
									patchloc = patchsrv + mp[:patchfile]
									patchfile = mp[:patchfile]
								end
								if batch_file
									file.puts("curl -O #{patchloc}")
									file.puts("#{patchfile} /q /z")
								else
									file.puts("strFileURL = \"#{patchloc}\"")
									file.puts("strHDLocation = \"#{patchfile}\"")
									file.puts("Set objXMLHTTP = CreateObject(\"MSXML2.XMLHTTP\")")
									file.puts("objXMLHTTP.open \"GET\", strFileURL, false")
									file.puts("objXMLHTTP.send()")
									file.puts("If objXMLHTTP.Status = 200 Then")
									file.puts("Set objADOStream = CreateObject(\"ADODB.Stream\")")
									file.puts("objADOStream.Open")
									file.puts("objADOStream.Type = 1")
									file.puts("objADOStream.Write objXMLHTTP.ResponseBody")
									file.puts("objADOStream.Position = 0")
									file.puts("Set objFSO = Createobject(\"Scripting.FileSystemObject\")")
									file.puts("If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation")
									file.puts("Set objFSO = Nothing")
									file.puts("objADOStream.SaveToFile strHDLocation")
									file.puts("objADOStream.Close")
									file.puts("Set objADOStream = Nothing")
									file.puts("End if")
									file.puts("Set objXMLHTTP = Nothing")
									file.puts("Set filesys = CreateObject(\"Scripting.FileSystemObject\")")
									file.puts("Set filetxt = filesys.OpenTextFile(\"patcher.bat\", 8, True)")
									file.puts("filetxt.WriteLine(\"#{patchfile} /q /z\")")
									file.puts("filetxt.Close")
								end
							end
						end
					end

					# Clean Up and Notify the User
					patching_targets.each do |pt|
						if batch_file
							ext = "bat"
							File.open(pt + "_unsploitable_patcher.#{ext}", 'a') do |file|
								file.puts("pause")
								file.puts("shutdown -r")
							end
						else
							ext = "vbs"
							File.open(pt + "_unsploitable_patcher.#{ext}", 'a') do |file|
								file.puts("Set filesys = CreateObject(\"Scripting.FileSystemObject\")")
								file.puts("Set filetxt = filesys.OpenTextFile(\"patcher.bat\", 8, True)")
								file.puts("filetxt.WriteLine(\"pause\")")
								file.puts("filetxt.WriteLine(\"shutdown -r\")")
								file.puts("filetxt.Close")
								file.puts("Set oShell = CreateObject(\"WScript.Shell\")")
								file.puts("strCmd = \"patcher.bat\"")
								file.puts("oShell.Run(strCmd)")
								file.puts("Set oShell = Nothing")
							end
						end

						newfile = pt + "_unsploitable_patcher_#{timestamp}.#{ext}"
						File.rename(pt + "_unsploitable_patcher.#{ext}", newfile)
						print_good(" #{pt} Patch Script: #{newfile} (Upload and Execute, Delete When Finished)")
					end
				else
					print_status("No Missing Patches Found")
				end
				
			end

			def cmd_unsploit_show(*args)
				# Define Options
				opts = Rex::Parser::Arguments.new(
					"-f"   => [ true, "Comma Separated List of IP's and Ranges to Exclude"],
					"-h"   => [ false, "Command Help"]
				)

				# Variables
				range = []

				# Parse options
				opts.parse(args) do |opt, idx, val|
					case opt
						when "-f"
		                                	range = val.gsub(" ","").split(",")
						when "-h"
							print_line(opts.usage)
							return
					end
				end

				# Build and Display Missing Patches
				missing_patches = build_matches(range)

				if missing_patches.length <= 0
					print_status("No Missing Patches Found")
				end
			end
		end



		def initialize(framework, opts)
			super
			add_console_dispatcher(Unsploitable)
			print_status("Unsploitable - One Shot - Loaded")
		end

		def cleanup
			remove_console_dispatcher("unsploitable")
		end

		def name
			"unsploitable"
		end

		def desc
			"Automatically Patch Metasploitable Vulnerabilities - One Shot"
		end

	end
end
