#Requires bundler
#Type 'gem install bundler' to install bundler
#type 'bundle install' to install requirements. Ensure the Gemfile is in the same directory as the script.
#Fuzzxor uses wfuzz. Automates the process much quicker.

puts <<-'EOF'

                         .-') _    .-') _) (`-.                 _  .-')   
                        (  OO) )  (  OO) )( OO ).              ( \( -O )  
   ,------.,--. ,--.  ,(_)----. ,(_)----.(_/.  \_)-..-'),-----. ,------.  
('-| _.---'|  | |  |  |       | |       | \  `.'  /( OO'  .-.  '|   /`. ' 
(OO|(_\    |  | | .-')'--.   /  '--.   /   \     /\/   |  | |  ||  /  | | 
/  |  '--. |  |_|( OO |_/   /   (_/   /     \   \ |\_) |  |\|  ||  |_.' | 
\_)|  .--' |  | | `-' //   /___  /   /___  .'    \_) \ |  | |  ||  .  '.' 
  \|  |_) ('  '-'(_.-'|        ||        |/  .'.  \   `'  '-'  '|  |\  \  
   `--'     `-----'   `--------'`--------'--'   '--'    `-----' `--' '--' 
                 |___/                       
EOF


require "rubygems"
require "highline/import"

def option_1
	system("clear")
	puts("Loading Quickscan")
	system("/root/pwn/fuzzer_quickhits")
	exit
end

def option_2
	system("clear")
	puts("Loading Fullscan")
	system("/root/pwn/fuzzer")
	exit
end

def option_3
	system("clear")
	puts("Loading IIS Scan")
	system("/root/pwn/fuzzer_IIS")
	exit
end

def option_4
	system("clear")
	puts("Loading PHP scan")
	system("/root/pwn/fuzzer_php")
	exit
end

def option_5
	system("clear")
	puts("Loading LDAP scan")
	system("/root/pwn/fuzzer_LDAP")
	exit
end

def option_6
	system("clear")
	puts("Loading LFI scan")
	system("/root/pwn/fuzzer_LFI")
	exit
end

def option_7
	system("clear")
	puts("Loading Custom Scan")
	system("/root/pwn/fuzzer_customscan_withcookie")
	exit
end

def option_8
	system("clear")
	puts("Loading Post Request")
	system("/root/pwn/fuzzer_postrequest")
	exit
end

loop do
	choose do |menu|
	menu.prompt = "Fuzzxor Scan options: "
	menu.choice("1 Fuzz quickscan") { option_1() }
	menu.choice("2 Fuzz Full Scan") { option_2() }
	menu.choice("3 Fuzz IIS") { option_3() }
	menu.choice("4 Fuzz PHP") { option_4() }
	menu.choice("5 Fuzz LDAP") { option_5() }
	menu.choice("6 Fuzz LFI") { option_6() }
	menu.choice("7 Fuzz with cookie and wordlist") { option_7() }
	menu.choice("8 FUzz Post Request") { option_8() }
	menu.choice("0 Exit") { exit }
	end
end




