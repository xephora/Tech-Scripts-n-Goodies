require "rubygems"
require "highline/import"

def opt_1
	system("clear")
	system("lib/ApacheC")
	exit
end

def opt_2
	system("clear")
	system("lib/postgC")
	exit
end

def opt_3
	system("clear")
	system("lib/sshC")
	exit
end

def opt_4
        system("clear")
        system("lib/findP")
        exit
end

def opt_5
        system("clear")
        system("lib/killP")
        exit
end

def opt_6
        system("clear")
        system("lib/kill_import")
        exit
end

def opt_7
        system("clear")
        system("lib/killvpn")
        exit
end


loop do
	choose do |menu|
	menu.prompt = "Service Control: "
	menu.choice("1 Apache Service") { opt_1() }
	menu.choice("2 Postgres Service") { opt_2() }
	menu.choice("3 SSH Service") { opt_3() }
	menu.choice("4 Find a port") { opt_4() }
	menu.choice("5 Kill a port") { opt_5() }
	menu.choice("6 Kill Import") { opt_6() }
	menu.choice("7 Kill VPN OpenVPN") { opt_7() }
	menu.choice("0 Exit") { exit }
	end
end
