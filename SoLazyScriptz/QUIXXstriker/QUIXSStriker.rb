#This script uses XSStriker.
#https://github.com/s0md3v/XSStrike
#
#Dependencies:
#tld
#requests
#fuzzywuzzy
#
#git clone https://github.com/s0md3v/XSStrike
#xss scripts are stored in the same folder as QUIXSStriker
#Move your XSS scripts in /root/pwn/xsstriker directory and your QUIXSStriker will work.

puts <<-'EOF'
 ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄       ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄    ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌     ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌ ▀▀▀▀█░█▀▀▀▀  ▐░▌   ▐░▌ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░▌ ▐░▌ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌       ▐░▌ ▐░▌  ▐░▌          ▐░▌               ▐░▌     ▐░▌       ▐░▌     ▐░▌     ▐░▌▐░▌  ▐░▌          ▐░▌       ▐░▌
▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌        ▐░▐░▌   ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌░▌   ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌
▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌         ▐░▌    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌     ▐░▌     ▐░░▌    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌     ▐░▌        ▐░▌░▌    ▀▀▀▀▀▀▀▀▀█░▌ ▀▀▀▀▀▀▀▀▀█░▌     ▐░▌     ▐░█▀▀▀▀█░█▀▀      ▐░▌     ▐░▌░▌   ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀ 
▐░░░░░░░░░░░▌▐░▌       ▐░▌     ▐░▌       ▐░▌ ▐░▌            ▐░▌          ▐░▌     ▐░▌     ▐░▌     ▐░▌       ▐░▌     ▐░▌▐░▌  ▐░▌          ▐░▌     ▐░▌  
 ▀▀▀▀▀▀█░█▀▀ ▐░█▄▄▄▄▄▄▄█░▌ ▄▄▄▄█░█▄▄▄▄  ▐░▌   ▐░▌  ▄▄▄▄▄▄▄▄▄█░▌ ▄▄▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌      ▐░▌  ▄▄▄▄█░█▄▄▄▄ ▐░▌ ▐░▌ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌      ▐░▌ 
        ▐░▌  ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌     ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
         ▀    ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀       ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀       ▀       ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀    ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀ 
                                                                                                                                                     
EOF

require "rubygems"
require "highline/import"

def option_1
	system("clear")
	puts("Loading XSS QuickScan")
	system("/root/pwn/xsstriker/xssQuick")
	exit
end

def option_2
	system("clear")
	puts("Loading XSS FullScan")
	system("/root/pwn/xsstriker/xssFull")
	exit
end

def option_3
	system("clear")
	puts("Loading XSS Crawl")
	system("/root/pwn/xsstriker/xssCrawl")
	exit
end

def option_4
	system("clear")
	puts("Loading XSS Fuzzer")
	system("/root/pwn/xsstriker/xssFuzzer")
	exit
end

def option_5
	system("clear")
	puts("Loading XSS PATHScan")
	system("/root/pwn/fuzzer_LDAP")
	exit
end

def option_6
	system("clear")
	puts("Loading POST Data")
	system("echo helooooooooooo")
	exit
end

loop do
	choose do |menu|
	menu.prompt = "QUIXSStriker: "
	menu.choice("1 XSS QuickScan") { option_1() }
	menu.choice("2 XSS FullScan") { option_2() }
	menu.choice("3 XSS Crawl") { option_3() }
	menu.choice("4 XSS Fuzzer") { option_4() }
	menu.choice("5 XSS PATHScan") { option_5() }
	menu.choice("6 XSS Post Data") { option_6() }
	menu.choice("0 Exit") { exit }
	end
end