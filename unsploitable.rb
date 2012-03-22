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

module Msf
	###
#
# This class hooks all session creation events and allows automated interaction
#
###

class Plugin::AutoPostExploit < Msf::Plugin

	include Msf::SessionEvent

	def on_session_open(session)
		return if not session.type == 'meterpreter'
		if (session.interactive?)
			host,port = session.tunnel_peer.split(':')
			print_status("Unsploitable Initiated: #{host} - #{session.via_exploit}")

			basedir = Msf::Config.install_root + "/data/unsploitable/"

			session.load_stdapi
			session.load_priv
			session.load_incognito

			session.init_ui(session.input, Rex::Ui::Text::Output::Stdio.new)
	
			osver = session.sys.config.sysinfo['OS']

			custom_patches = open(basedir + 'custom.db').grep(/(#{session.via_exploit}|^\|)/)
			provided_patches = open(basedir + 'patches.db').grep(/(#{session.via_exploit}|^\|)/)

			patches = custom_patches | provided_patches

			final = false
			kb = nil
			cve = nil
			mssb = nil

			patches.each do |patch|
				patch.chomp!
				elements = patch.split("|")
                                unless elements[1].nil? || elements[1] == 0 || elements[1].length == 0
					if (osver =~ /#{elements[1]}/)
                                                final = true
                                        else
                                                final = false
                                                next
                                        end
                                else
                                        final = true
                                end
				unless elements[2].nil? || elements[2] == 0 || elements[2].length == 0
					if (osver =~ /#{elements[2]}/)
						final = true
					else
						final = false
						next
					end
				else
					final = true
				end
				unless elements[3].nil? || elements[3] == 0 || elements[3].length == 0
                                        if (session.platform =~ /#{elements[3]}/)
                                                final = true
                                        else
						final = false
                                                next
					end
                                else
                                        final = true
                                end

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
				print_status("Patch Found...")
				if kb || cve || mssb
					print_status("Patching #{final}...(#{kb} #{cve} #{mssb})")
				else
					print_status("Patching #{final}...")
				end

				if (osver =~ /win/i)
					session.run_cmd('getsystem')
					session.run_cmd("migrate #{session.sys.process['explorer.exe']}")
				end

				if (final =~ /exe|msu/)
					if (final =~ /^http\:/)
						session.run_cmd("upload " + basedir + "/.curl/" + "libcurl.dll .")
						session.run_cmd("upload " + basedir + "/.curl/" + "libeay32.dll .")
						session.run_cmd("upload " + basedir + "/.curl/" + "libssl32.dll .")
						session.run_cmd("upload " + basedir + "/.curl/" + "curl.exe .")
					else
						session.run_cmd("upload " + basedir + "/patches/" + "#{final} .")
					end
                                        prereq = false
                                        prereqs = open(basedir + 'prereq.db').grep(/\|/)
                                        prereqs.each do |line|
						line.chomp!
						elements = line.split("|")
						if (osver =~ /#{elements[0]}/) && (session.platform =~ /#{elements[1]}/)
							session.run_cmd("upload " + basedir + "/patches/" + "#{elements[2]} .")
							prereq = "#{elements[2]} #{elements[3]}"
							break
						end
					end
					File.open("update.bat", 'w') do |file|
						if (final =~ /^http\:/)
							file.puts "curl -O #{final}"
							final_parts = final.split("/")
							final = final_parts.pop
						end
						if (prereq)
							file.puts "#{prereq}"
						end
						file.puts "#{final} /q /z"
						file.puts "shutdown -r"
					end
					session.run_cmd("upload " + basedir + "update.bat .")
					session.run_cmd("execute -f update.bat")
					File.delete("update.bat")
				end

				if (final =~ /rpm/)
					session.run_cmd("upload #{final}")
					session.shell_write("rpm -uh #{final}")
				end

				if (final =~ /deb/)
					session.run_cmd("upload #{final}")
					session.shell_write("dpkg -i #{final}")
				end
			else
				print_status("No Patches Found")
			end

			session.init_ui(session.input, Rex::Ui::Text::Output::Stdio.new)
			print_status("Unsploitable Complete, Enjoy Your Session")
			return
		end

	end

	def initialize(framework, opts)
		super
		self.framework.events.add_session_subscriber(self)
	end

	def cleanup
		self.framework.events.remove_session_subscriber(self)
	end

	def name
		"unsploitable"
	end

	def desc
		"Automatically Patch Metasploitable Vulnerabilities"
	end

end
end
