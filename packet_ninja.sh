
#!/bin/bash
rm -rf /tmp/.shellcode.txt
echo $'\e[1;34m'"                                         
                       @@@@,@@@@@@@@@@@@@@@@@@@@@@@@@@.@@@@.                               
                     .@@@(&@@@@@@@@@@@@@@@@@@@@@@@@@@@@&(@@@,                              
                     @@@%@@@%.(@@@@@@@@@@@@@@@@@@@@(.%@@@%@@@                              
                    /@@&@ /@@@@@@@@@@@@@@@@@@@@@@@@@@@@/ @&@@(                             
                    @@@*#@@@@@%                    %@@@@@#*@@@                             
           ,%&(     @@&&@@@%                          %@@@&&@@                             
        #@@(///@@. .@@.@@@*                            *@@@.@@.                            
      %@@@@@@@@@.@@ @@,@@& *%&@@*                /@@&%* &@@,@@                             
    ,@@@@@@@@@*  @@ @@/@@&       &@&(,      *(@@&       &@@/@@                             
   @@@@&&%## @@@@ @/&@@@@@.     @@#            #@@     .@@@@@&                             
            @@%@@@@@,@@@@@@.         .@%@@@@.         .@@@@@@,                             
           @@&@@@@@@ @@@@@@@@@(...,&@&@@@@@@@@&,...(@@@@@@@@@                              
           @@@@@@&@  #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                              
           #@@@@@@    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                               
            &@@@@      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  
      ========================================================================"$'\e[0m'

echo $'\e[1;32m'"        Packet Ninja v3 - packet crafting tool. Made with Scapy. By: "$'\e[1;31m'"anurag"
echo $'\e[1;34m'"      ========================================================================"$'\e[0m'
read -n 1 -s -r -p "                             Press any key to start "


echo
echo 
echo    $'\e[1;31m'"  IDS testing : "$'\e[0m'
echo    "  1)" $'\e[1;32m'"Scan, Ping & Attack Testing "$'\e[0m'
echo    "  2)" $'\e[1;32m'"IDS Evasion Testing "$'\e[0m'
echo
echo    $'\e[1;31m'"  Payload Encryption - R&D : "$'\e[0m'
echo    "  3)" $'\e[1;32m'"File sender "$'\e[0m'
echo    "  4)" $'\e[1;32m'"Packet - Payload encryption "$'\e[0m'
echo 	"  5)" $'\e[1;32m'"File/packet sniffer "$'\e[0m'
#echo    "  4)" $'\e[1;32m'"Send empty/bogus payload"$'\e[0m'
#echo    "  5)" $'\e[1;32m'"Packet payload encryption - RC4"$'\e[0m'
#echo    "  5)" $'\e[1;32m'"Shellcode Tester "$'\e[0m'
echo 
echo	"  i)" $'\e[1;33m'"Initial Setup / update"$'\e[0m'
echo    "  a)" $'\e[1;31m'"AES Encrypted Tunnel "$'\e[0m'    
echo    "  p)" $'\e[1;32m'"Pcap Editor - edit or replay pcap " $'\e[0m'
echo 	"  m)" $'\e[1;34m'"More Info"$'\e[0m'
echo    "  q)" $'\e[1;34m'"Quit"$'\e[0m' 
echo
read -p $'\e[1;31m'"  option: "$'\e[0m' choice 
echo	

case $choice in

    2)
        exec sudo python main_config/packet_ninja_evasion_v3.py
        clear
        
        ;;
    
    1)  
        exec sudo python main_config/packet_ninja_attack_v3.py
        clear
        
        ;;
    q)
        rm -rf /tmp/.shellcode.txt
        echo "  bye"
        exit 1
        
        ;;

    4)  echo
        echo $'\e[1;34m'"==========================================================="$'\e[0m'
        echo "                 A E S   E N C R Y P T O R                 "
        echo $'\e[1;34m'"==========================================================="$'\e[0m'
        echo "  with   S A L T   a n d   K E Y   G E N E R A T O R  "
        echo $'\e[1;34m'"==========================================================="$'\e[0m'
        echo "             by anurag, always use python2           "
        echo $'\e[1;34m'"-----------------------------------------------------------"$'\e[0m'
        echo 
	echo $'\e[1;34m'"  1)"$'\e[0m' " AES Encryption  "
	echo $'\e[1;34m'"  2)"$'\e[0m' " AES Decryption  "
	echo $'\e[1;34m'"  3)"$'\e[0m' " Send packets with AES key/payload "
        echo $'\e[1;34m'"  4)"$'\e[0m' " Create packets with bogus data    "
	echo $'\e[1;34m'"  0)"$'\e[0m' " Exit		  "
	echo
        read -p $'\e[1;34m'"packetninja> "$'\e[0m' option
        echo

        case $option in
            
	1)  echo 
	    read -p $'\e[1;35m'"Input file eg(file.txt) : "$'\e[0m' -e file
            exec python main_config/AES_packet_craft/aes_encryptor_v3.py $file
            ;;
        2)  read -p $'\e[1;35m'"input encrypted file eg(file.bin): "$'\e[0m' -e encrypted
            echo
	    read -p $'\e[1;35m'"input key file eg(key.bin): "$'\e[0m' -e keyfile
            exec python main_config/AES_packet_craft/aes_decryptor_v3.py $encrypted $keyfile
            ;;
        3)  
	    read -p $'\e[1;35m'"  input encrypted payload file: "$'\e[0m' -e encryptedfile
            echo
            read -p $'\e[1;35m'"  input key file: "$'\e[0m' -e keyfile
            echo
	    exec python main_config/AES_packet_craft/send_key_data.py $encryptedfile $keyfile
            ;;
        4)
            exec python main_config/AES_packet_craft/send_empty_fake.py
            ;;

        0)  exit 1
            ;;
        *)  echo "  Invalid option"
            ;;
        esac
        
        ;;


    5s)  echo $'\e[1;37m'"  ======================================="$'\e[0m'
        echo $'\e[1;35m'"              Shellcode Tester           "$'\e[0m'
        echo
	echo $'\e[1;35m'"     encode, compile and exec shellcode  "$'\e[0m'
	echo $'\e[1;37m'"  ======================================="$'\e[0m'
        echo
        echo $'\e[1;37m'"  1) encode/send shellcode                "$'\e[0m'
        echo $'\e[1;37m'"  2) compile shellcode                    "$'\e[0m'
        echo $'\e[1;37m'"  0) exit                                 "$'\e[0m'
	echo
	read -p $'\e[1;35m'"  shellcode_tester> "$'\e[0m' option 
        case $option in
            
	1)  echo
            read -p $'\e[1;34m'"shellcode file: "$'\e[0m' -e shellcode
            exec python main_config/xor_shellcode/main-xor-encoder.py $shellcode
            ;;

        2)  exec sudo main_config/xor_shellcode/./GCC_compiler.sh
            ;;

	0)  exit 1
            ;;

        *)  echo $'\e[1;31m'"  Invalid option"$'\e[0m'
            ;;

        esac
        
        ;;


    3)  echo
        echo $'\e[1;32m'"==========================================================="$'\e[0m'
        echo "             F I L E   S E N D E R                "
        echo $'\e[1;32m'"==========================================================="$'\e[0m'
        echo "     by anurag, made with Scapy, always use python2           "
        echo $'\e[1;32m'"-----------------------------------------------------------"$'\e[0m'
        echo 
	read -p $'\e[1;32m'"  Input file: "$'\e[0m' -e importfile
	echo
        echo
        exec sudo python main_config/org_send/importSendfile.py $importfile
        
	;;

    i)  
        exec sudo main_config/setup.sh
        echo $'\e[1;32m'"  All packages are installed !! "$'\e[0m'
        
        ;;

    m)  
        clear
        sleep 0.5s
	echo $'\e[1;32m'
        cat main_config/README.txt | less
        echo $'\e[0m'
        
        ;;

    a)  
        echo $'\e[1;33m'"  ----------------------------------------- "$'\e[0m'
        echo "          AES-encrypted Server/client       "
        echo $'\e[1;33m'"  ----------------------------------------- "$'\e[0m'
	echo
	echo $'\e[1;31m'"  1)"$'\e[0m'" AES server side"
	echo $'\e[1;31m'"  2)"$'\e[0m'" AES client side"
        echo $'\e[1;31m'"  0)"$'\e[0m'" Exit           "
        echo
        read -p $'\e[1;33m'"  Option> "$'\e[0m' choices
        case $choices in
	           
	1)  echo
            exec python3 main_config/AES_tunnel/serverside.py
            ;;

        2)  exec sudo python3 main_config/AES_tunnel/clientaes_v2.py
            ;;

	0)  exit 1
            ;;

        *)  echo $'\e[1;31m'"  Invalid option"$'\e[0m'
            ;;

        esac
        
        ;;
    
    p)  
        echo $'\e[1;31m'"  ----------------------------------------- "$'\e[0m'
        echo "               PCAP Editor v1               "
        echo $'\e[1;31m'"  ----------------------------------------- "$'\e[0m'
        echo $'\e[1;31m'"  created with scapy, tcpdump by anurag (version 1)   "$'\e[0m'
	echo
	echo $'\e[1;32m'"  1)"$'\e[0m'" Replace packet data  "
	#echo $'\e[1;32m'"  2)"$'\e[0m'" Encrypt Pcap w/ AES  "
	#echo $'\e[1;32m'"  3)"$'\e[0m'" Decrypt Pcap w/ AES  "
	echo $'\e[1;32m'"  2)"$'\e[0m'" Edit IP address/port "
	echo $'\e[1;32m'"  3)"$'\e[0m'" Replay Pcap  "
        echo $'\e[1;32m'"  4)"$'\e[0m'" Read Pcap file "
	echo $'\e[1;32m'"  0)"$'\e[0m'" Exit "
	echo
        read -p $'\e[1;32m'"  Option> "$'\e[0m' choices
        echo
	read -p $'\e[1;32m'"  Input pcap file: "$'\e[0m' -e pcapfile
	exec python main_config/pcap_editor.py $choices $pcapfile 
	echo
        
	;;


    5)  exec sudo python main_config/completeSniffer.py
        echo
        
	;;

    *)  echo $'\e[1;33m'"  ------------------------------------"$'\e[0m'
        echo $'\e[1;33m'"    invalid option ! Press q to quit. "$'\e[0m'
        echo $'\e[1;33m'"  ------------------------------------"$'\e[0m'
        echo
        exec ./packet_ninja.sh
        exit 1
        
        ;;

esac


# - rc4 payload encryption - removed on jan 16 th 2020
#
#    9)
#	echo $'\e[1;35m'"  ***********************************************************"$'\e[0m' 
#	echo $'\e[0m'"                  RC4 Packet Payload Encryption              "$'\e[0m' 
#        echo $'\e[1;35m'"  ************************************************************"$'\e[0m'
#        echo $'\e[0m'"           rc4 encryption, pycryptodome by: anurag           "$'\e[0m'
#	echo $'\e[1;35m'"  ************************************************************"$'\e[0m' 
#	echo $'\e[1;35m'"  1)"$'\e[0m'" RC4 Encryption  "
#	echo $'\e[1;35m'"  2)"$'\e[0m'" RC4 Decryption  "
#	echo $'\e[1;35m'"  3)"$'\e[0m'" Send packets with RC4 payload/key "
#	echo $'\e[1;35m'"  0)"$'\e[0m'" Exit		  "
#	echo
#	read -p $'\e[1;35m'"  rc4PayloadEncryption> "$'\e[0m' option 
#	echo
#        case $option in
#            
#	1)  read -p $'\e[1;35m'"  input file eg(file.txt) : "$'\e[0m' -e file
#            exec python main_config/rc4_packet_craft/rc4_encryptor_v1.py $file
#            ;;
#        2)  read -p $'\e[1;35m'"  input encrypted file eg(file.txt): "$'\e[0m' -e encrypted
#	    read -p $'\e[1;35m'"  input key file eg(key.txt): "$'\e[0m' -e keyfile
#           exec python main_config/rc4_packet_craft/rc4_decryptor_v1.py $encrypted $keyfile
#            ;;
#	3)  read -p $'\e[1;35m'"  input encrypted file: "$'\e[0m' -e encryptedfile
#	    echo
 #           read -p $'\e[1;35m'"  input key file: "$'\e[0m' -e keyfile
#	    exec python main_config/rc4_packet_craft/send_key_data_rc4.py $encryptedfile $keyfile
#	    ;;
#	0)  exit 1
 #           ;;

  #      *)  echo $'\e[1;31m'"  Invalid option"$'\e[0m'
 #           ;;
#
 #       esac
        
#        ;;




# Extra ASCII artwork/banner
# (do not delete)

#declare -a arr
#arr[1]='  
#  _____________________________ __________________   _____   _____________   ________________ 			
#  ___  __ \__    |_  ____/__  //_/__  ____/__  __/   ___  | / /___  _/__  | / /_____  /__    |			
#  __  /_/ /_  /| |  /    __  ,<  __  __/  __  /      __   |/ / __  / __   |/ /___ _  /__  /| |			
#  _  ____/_  ___ / /___  _  /| | _  /___  _  /       _  /|  / __/ /  _  /|  / / /_/ / _  ___ |				
#  /_/     /_/  |_\____/  /_/ |_| /_____/  /_/        /_/ |_/  /___/  /_/ |_/  \____/  /_/  |_|'
#
#
#arr[2]="  ____            _        _         _   _ _        _       
#         |  _ \ __ _  ___| | _____| |_      | \ | (_)_ __  (_) __ _ 
#         | |_) / _' |/ __| |/ / _ \ __|     |  \| | | '_ \ | |/ _' |
#         |  __/ (_| | (__|   <  __/ |_      | |\  | | | | || | (_| |
#         |_|   \__/_|\___|_|\_\___|\__|     |_| \_|_|_| |_|/ |\__/_|
#                                                         |__/         "                                  
#rand=$[$RANDOM % ${#arr[@]}]
#( IFS=$'\n'; echo "${arr[$rand]}")
#echo $'\e[1;34m'"   
#===============================================================================
#arr[1]='
#           	                                             #              #                        
#                                                            ##             ##                       
#  ####### ########  ###### ###  ## ######## ########        ###  ##    ### ###  ## ######## ########
#        ##      ## ###     ### ##              ###          #### ##    ### #### ##      ##        ##
#   ######  ####### ###     #####    #######    ###          #######    ### #######      ##   #######
#   ###     ###  ## ###     ### ##   ###        ###          ### ###    ### ### ###      ##   ###  ##
#   ###     ###  ##  ###### ###  ##  #######    ###          ###  ##    ### ###  ##  ######   ###  ## 
#                                                                  #              #                   '
