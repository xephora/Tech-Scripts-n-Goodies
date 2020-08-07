puts <<-'EOF'                                                
   __  __            __                          
  69MM69MM          69MM                         
 6M' 6M' `         6M' `                         
_MM__MM____   ___ _MM_____   ___  _____  ___  __ 
MMMMMMMM`MM    MM MMMM`MM(   )P' 6MMMMMb `MM 6MM 
 MM  MM  MM    MM  MM  `MM` ,P  6M'   `Mb MM69 " 
 MM  MM  MM    MM  MM   `MM,P   MM     MM MM'    
 MM  MM  MM    MM  MM    `MM.   MM     MM MM     
 MM  MM  MM    MM  MM    d`MM.  MM     MM MM     
 MM  MM  YM.   MM  MM   d' `MM. YM.   ,M9 MM     
_MM__MM_  YMMM9MM__MM__d_  _)MM_ YMMMMM9 _MM_    
                                                                                                                                                   
EOF


require "rubygems"
require "highline/import"

def option_1
        system("clear")
        puts("Loading scanner")
        system("ffuf_scripts/ffuf_main")
        exit
end

def option_2
	system("clear")
	puts("Loading Fullscan")
	system("/root/pwn/toolk1t/3_Content-Discovery/Fuzzxor/ffuf_scripts/ffuf_full")
	exit
end

def option_3
        system("clear")
        puts("Loading Websters")
        system("ffuf_scripts/ffuf_websters")
        exit
end

loop do
	choose do |menu|
	menu.prompt = "ffuf Scan options: "
	menu.choice("1 ffuf main") { option_1() }
	menu.choice("2 ffuf fullscan") { option_2() }
	menu.choice("3 ffuf websters") { option_3() }
	menu.choice("0 Exit") { exit }
	end
end
