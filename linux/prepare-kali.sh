#!/bin/bash

# Well, entire Kali installation assume that we are normally working as root on our Kali.
# I know that assumption sucks to its root, but I wanted to avoid every "permission denied" issue and I was too lazy
# to get it done properly as a non-root.
if [ $EUID -ne 0 ]; then
  echo "This script must be run as root."
  exit 1
fi

ROOT_DIR=/root

git_clone() {
  git clone --recurse-submodules $1
}

apt update ; apt upgrade -y
apt install -y git build-essential binutils-dev vim python3 libunwind-dev python unzip python-pip python3-pip python3-venv python3-setuptools libssl-dev autoconf automake libtool python2.7-dev python3.7-dev python3-tk jq awscli npm graphviz golang
pip3 install virtualenv awscli wheel boto3 botocore
pip install virtualenv wheel boto3 botocore

cd $ROOT_DIR
mkdir {data,dev,tools,utils,misc,work}

# ------------------------------------------------------ 

cd $ROOT_DIR/data
git_clone https://github.com/fuzzdb-project/fuzzdb.git
git_clone https://github.com/danielmiessler/SecLists.git
git_clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
git_clone https://github.com/j0bin/Pentest-Resources.git
git_clone https://github.com/minimaxir/big-list-of-naughty-strings.git
git_clone https://github.com/1N3/IntruderPayloads
git_clone https://github.com/duyetdev/bruteforce-database.git
wget https://gist.githubusercontent.com/mgeeky/8b7b1c8d9fe8be69978d774bddb6e382/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt

# ------------------------------------------------------ 

cd $ROOT_DIR/tools

mkdir {bruteforce,clouds,deserialization,exploitdev,windows,redteam,recon,reversing,web,infra,fuzzers,linux,misc,powershell,ssl,sourceaudit,shells,wireless}

git_clone https://github.com/mgeeky/Penetration-Testing-Tools

pushd bruteforce
git_clone https://github.com/lanjelot/patator.git
git_clone https://github.com/galkan/crowbar.git
git clone --depth=1 --branch=master https://www.github.com/landgrey/pydictor.git && chmod 755 pydictor/pydictor.py
popd

pushd clouds
mkdir {aws,azure,gcp,kubernetes}

# Multi-cloud tools
git_clone https://github.com/nccgroup/ScoutSuite.git ; cd ScoutSuite ; virtualenv -p python3 venv ; source venv/bin/activate ;  pip install -r requirements.txt ; cd ..
git_clone https://github.com/Ice3man543/SubOver
cd SubOver
go build
chmod +x SubOver
cd ..

# AWS related
cd aws
git_clone https://github.com/RhinoSecurityLabs/pacu.git ; cd pacu ; bash install.sh ; cd ..
git_clone https://github.com/Alfresco/prowler.git
git_clone https://github.com/sa7mon/S3Scanner.git
git_clone https://github.com/nahamsec/lazys3.git
git_clone https://github.com/andresriancho/nimbostratus.git
git_clone https://github.com/duo-labs/cloudmapper.git ; cd cloudmapper/ ; pipenv install --skip-lock ; pipenv shell ; cd ..
git_clone https://github.com/awslabs/aws-security-benchmark.git
git_clone https://github.com/cloudsploit/scans.git
mv scans cloudsploit
cd cloudsploit
npm install
cd plugins/azure
cp -r virtualmachines virtualMachines
cp -r blobservice blobService
cp -r resourceGroups resourcegroups
cp storageAccounts/storageAccountsEncryption.js storageaccounts/
cd ../../..
git_clone https://github.com/dagrz/aws_pwn.git
git_clone https://github.com/MindPointGroup/cloudfrunt.git
git_clone https://github.com/nccgroup/PMapper.git
git_clone https://github.com/tomdev/teh_s3_bucketeers.git
git_clone https://github.com/carnal0wnage/weirdAAL.git ; cd weirdAAL ; apt-get install -y python3-venv ; python3 -m venv weirdAAL ; source weirdAAL/bin/activate ; pip3 install -r requirements.txt ; python3 create_dbs.py ; cp env.sample .env ; cd ..
cd ..
popd

pushd deserialization
git_clone https://github.com/matthiaskaiser/jmet.git
git_clone https://github.com/joaomatosf/JavaDeserH2HC.git
git_clone https://github.com/pwntester/ysoserial.net.git
git_clone https://github.com/frohoff/ysoserial.git
git_clone https://github.com/NetSPI/JavaSerialKiller.git
git_clone https://github.com/joaomatosf/jexboss.git
wget 'https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar' -O ysoserial/ysoserial.jar
popd

pushd exploitdev
git_clone https://github.com/sashs/Ropper.git
git_clone https://github.com/longld/peda.git
git_clone https://github.com/Gallopsled/pwntools.git
git_clone https://github.com/packz/ropeme.git
git_clone https://github.com/mgeeky/Exploit-Development-Tools.git
popd

pushd infra
git_clone https://github.com/SpiderLabs/Responder.git
git_clone https://github.com/DanMcInerney/net-creds.git
git_clone https://github.com/rofl0r/proxychains-ng.git
git_clone https://github.com/brav0hax/smbexec.git
git_clone https://github.com/inquisb/icmpsh.git
git_clone https://github.com/tomac/yersinia.git
git_clone https://github.com/threat9/routersploit.git
git_clone https://github.com/hatRiot/clusterd.git
popd

pushd fuzzers
git_clone https://github.com/googleprojectzero/domato.git
wget http://www.immunitysec.com/downloads/SPIKE2.9.tgz ; tar -xvzf SPIKE2.9.tgz ; rm SPIKE2.9.tgz
git_clone https://gitlab.com/akihe/radamsa.git
git_clone https://github.com/google/honggfuzz.git
cd honggfuzz
make -j 8
make install
cd ..
wget https://github.com/shellphish/fuzzer.git
wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar -xvzf afl-latest.tgz
rm afl-latest.tgz
cd $(find . -type d -name 'afl-*' -maxdepth 1 2>/dev/null)
make -j 8 ; make install
cd ..
git_clone https://github.com/d0c-s4vage/gramfuzz.git
git_clone https://github.com/nccgroup/Hodor.git
git_clone https://github.com/OpenRCE/sulley.git
git_clone https://github.com/renatahodovan/grammarinator.git
popd

pushd linux
git_clone https://github.com/Arr0way/linux-local-enumeration-script.git
git_clone https://github.com/CISOfy/lynis.git
popd

pushd misc
git_clone https://github.com/nullsecuritynet/tools.git
git_clone https://github.com/leebaird/discover.git
git_clone https://github.com/dxa4481/truffleHog.git
popd

pushd powershell
git_clone https://github.com/BloodHoundAD/BloodHound.git
git_clone https://github.com/EmpireProject/Empire.git
git_clone https://github.com/PowerShellMafia/PowerSploit.git
git_clone https://github.com/samratashok/nishang.git
popd

pushd recon
git_clone https://github.com/FortyNorthSecurity/EyeWitness.git
git_clone https://github.com/OWASP/Amass.git
git_clone https://github.com/michenriksen/gitrob.git
git_clone https://github.com/darkoperator/dnsrecon.git
git_clone https://github.com/smicallef/spiderfoot.git
git_clone https://bitbucket.org/LaNMaSteR53/recon-ng.git ; cd recon-ng ; pip install -r REQUIREMENTS ; cd ..
git_clone https://github.com/infosec-au/altdns.git
git_clone https://github.com/jhaddix/domain.git
mv domain jhaddix-enumall
cat <<EOT > jhaddix-enumall/config.py
reconPath = "$PWD/recon-ng/"
altDnsPath = "$PWD/altdns/"
EOT
cd jhaddix-enumall
chmod 755 enumall.py
cp $(find $ROOT_DIR/data/SecLists/Discovery/DNS/*knock*.txt) sorted_knock_dnsrecon_fierce_recon-ng.txt
cd ..

git_clone https://github.com/subfinder/subfinder.git
cd subfinder 
go build
chmod +x subfinder
cd ..
git_clone https://github.com/aboul3la/Sublist3r.git
git_clone https://github.com/michenriksen/aquatone.git
git_clone https://github.com/dxa4481/truffleHog.git
popd

pushd redteam
git_clone https://github.com/Veil-Framework/Veil.git
git_clone https://github.com/Veil-Framework/Veil-Evasion.git
git_clone https://github.com/pentestgeek/phishing-frenzy.git
git_clone https://github.com/trustedsec/social-engineer-toolkit.git
popd

pushd reversing
wget https://ghidra-sre.org/ghidra_9.0_PUBLIC_20190228.zip -O ghidra.zip ; unzip -d . ghidra.zip ; rm ghidra.zip
git_clone https://github.com/longld/peda.git ; echo "source $ROOT_DIR/tools/reversing/peda/peda.py" >> $ROOT_DIR/.gdbinit ; 
git_clone https://github.com/hugsy/gef.git
git_clone https://github.com/radare/radare2.git ; cd radare2 ; sys/install.sh ; r2pm init ; r2pm update ; pip install r2pipe ; cd ..
popd

pushd shells
git_clone https://github.com/BlackArch/webshells.git
git_clone https://github.com/Ne0nd0g/merlin.git
popd

pushd sourceaudit
git_clone https://github.com/presidentbeef/brakeman.git
git_clone https://github.com/wireghoul/graudit.git
popd

pushd ssl
git_clone https://github.com/rbsec/sslscan.git
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
git_clone https://github.com/tomato42/tlsfuzzer.git
popd

pushd web
git_clone https://github.com/mgeeky/tomcatWarDeployer.git
git_clone https://github.com/codingo/NoSQLMap.git
git_clone https://github.com/commixproject/commix.git
git_clone https://github.com/droope/droopescan.git
git_clone https://github.com/breenmachine/httpscreenshot.git
git_clone https://github.com/beefproject/beef/ ; pushd beef ; yes | ./install ; popd
git_clone https://github.com/mitmproxy/mitmproxy.git
git_clone https://github.com/sqlmapproject/sqlmap.git
git_clone https://github.com/RhinoSecurityLabs/SleuthQL
git_clone https://github.com/EnableSecurity/wafw00f.git
git_clone https://github.com/nodesecurity/eslint-plugin-security ; npm install --save-dev eslint-plugin-security
cat <<EOT >> $ROOT_DIR/.eslintrc
"plugins": [
  "security"
],
"extends": [
  "plugin:security/recommended"
]
EOT

git_clone https://github.com/epinna/tplmap.git
git_clone https://github.com/jekyc/wig.git
git_clone https://github.com/wpscanteam/wpscan.git
git_clone https://github.com/sullo/nikto.git
git_clone https://github.com/gw0/PadBuster.git
git_clone https://github.com/OJ/gobuster.git
git_clone https://github.com/GerbenJavado/LinkFinder.git
git_clone https://github.com/ticarpi/jwt_tool.git
git_clone https://github.com/dnoiz1/git-money.git
git_clone https://github.com/arthaud/git-dumper.git
git_clone https://github.com/mogwaisec/mjet.git
git_clone https://github.com/NickstaDB/BaRMIe.git
popd

pushd windows
git_clone https://github.com/gentilkiwi/mimikatz.git
git_clone https://github.com/brav0hax/smbexec.git
git_clone https://github.com/lgandx/Responder.git
git_clone https://github.com/SecureAuthCorp/impacket.git
cd impacket ; mkdir binaries ; cd binaries ; curl -s https://api.github.com/repos/ropnop/impacket_static_binaries/releases/latest | grep "browser_download_url.*exe" | cut -d : -f 2,3 | tr -d \" | wget -qi - ; cd ../../
popd

pushd wireless
git_clone https://github.com/brav0hax/easy-creds.git
git_clone https://github.com/s0lst1c3/eaphammer.git ; cd eaphammer ; ./kali-setup ; cd ..
git_clone https://github.com/derv82/wifite2.git ; cd wifite2 ; python setup.py install ; cd ..
popd


#
# Follow repos, collect 'requirements.txt' files and feed them into `pip install`.
# We avoid the hassle of using virtualenv here and there.
#
find . -name .git | while read line; do 
  echo $line
  pushd "$(dirname $line)"
  if [ -f 'requirements.txt' ]; then 
    pip install -r requirements.txt; 
    pip3 install -r requirements.txt; 
  elif [ -f 'Gemfile' ]; then
    bundle install
  fi
  popd
done

# Append some stuff to bashrc
cat <<'EOF' >> $ROOT_DIR/.bashrc

stty start undef

# To get Ctrl-s working (forward command search, i-search)
stty -ixon

#
# ENVIRONMENT VARIABLES
#

PROMPT_CHAR=$(if [ "$(whoami)" == "root" ] ; then echo "#" ; else echo "$" ; fi)
HOST_COLOR=$(if [ "$(whoami)" == "root" ] ; then echo "6" ; else echo "1" ; fi)

export PS1="\[\e[0;3${HOST_COLOR}m\]\H\[\e[0;37m\]|\[\e[0;32m\]\A\[\e[0;37m\]|\[\e[0;33m\]\w\[\e[0;3${HOST_COLOR}m\] ${PROMPT_CHAR} \[\e[1;0m\]"


# My aliases
alias ls='ls --color=auto'
alias ll='ls -l --color=auto'
alias la='ls -la'
alias l='ls -CF'
alias lsl="ls -lhFA | less"
alias ls-l="ls -l"

alias cd..="cd .."
alias ..='cd ..'
alias ...='cd ../../../'
alias ....='cd ../../../../'
alias .....='cd ../../../../'
alias .4='cd ../../../../'
alias .5='cd ../../../../..'

alias dudirs='for a in `find . -mindepth 1 -maxdepth 1 -type d`; do echo $a... ; du -csh "$a" 2> /dev/null | grep -v total ; done'

# Use less if output is bigger than screen
alias less="less -F -X -R"
alias ifconfig="sudo ifconfig -a"

alias reload=". ~/.bashrc"

# The Exits Family
alias ':q'='exit'
alias ':Q'='exit'
alias ':x'='exit'
alias ':X'='exit'
alias ':w'='exit'
alias ':W'='exit'
alias 'q'='exit'
alias 'Q'='exit'

alias sudo='sudo '
alias fuck='sudo $(history -p \!\!)'
alias mkdir="mkdir -pv"
alias wget="wget -c"
alias histg="history | grep"
alias remoteip="(curl -s https://api.ipify.org/ && echo)"
alias commandstat="history | awk '{CMD[$2]++;count++;}END { for (a in CMD)print CMD[a] \" \" CMD[a]/count*100 \"% \" a;}' | grep -v \"./\" | column -c3 -s \" \" -t | sort -nr | nl |  head -n10"

# Searchable process table
alias psg="ps aux | grep -v grep | grep -i -e VSZ -e"


# Copy working directory path
alias cpwd="pwd | tr -d "\n" | setclip"

alias meminfo='free -m -l -t'
 
## get top process eating memory
alias psmem='ps auxf | sort -nr -k 4'
alias psmem10='ps auxf | sort -nr -k 4 | head -10'
 
## get top process eating cpu ##
alias pscpu='ps auxf | sort -nr -k 3'
alias pscpu10='ps auxf | sort -nr -k 3 | head -10'

alias hex2raw="tr -d '\\\x' | xxd -r -p"
alias prettyjson='python -m json.tool'

function killallbyname() {
    sudo kill -9 $(psg $1 | fawk 2 | tail -n +2 | xargs)
}

function extract {
 if [ -z "$1" ]; then
    # display usage if no parameters given
    echo "Usage: extract <path/file_name>.<zip|rar|bz2|gz|tar|tbz2|tgz|Z|7z|xz|ex|tar.bz2|tar.gz|tar.xz>"
 else
    if [ -f "$1" ] ; then
        NAME=${1%.*}
        #mkdir $NAME && cd $NAME
        case "$1" in
          *.tar.bz2)   tar xvjf ./"$1"    ;;
          *.tar.gz)    tar xvzf ./"$1"    ;;
          *.tar.xz)    tar xvJf ./"$1"    ;;
          *.lzma)      unlzma ./"$1"      ;;
          *.bz2)       bunzip2 ./"$1"     ;;
          *.rar)       unrar x -ad ./"$1" ;;
          *.gz)        gunzip ./"$1"      ;;
          *.tar)       tar xvf ./"$1"     ;;
          *.tbz2)      tar xvjf ./"$1"    ;;
          *.tgz)       tar xvzf ./"$1"    ;;
          *.zip)       unzip ./"$1"       ;;
          *.Z)         uncompress ./"$1"  ;;
          *.7z)        7z x ./"$1"        ;;
          *.xz)        unxz ./"$1"        ;;
          *.exe)       cabextract ./"$1"  ;;
          *)           echo "extract: '$1' - unknown archive method" ;;
        esac
    else
        echo "'$1' - file does not exist"
    fi
  fi
}

# Get N column from the output.
# Usage, e.g.: df -h | fawk 2
function fawk {
    first="awk '{print "
    last="}'"
    cmd="${first}\$${1}${last}"
    eval $cmd
}

# ===================================
# Random number from specified range
#

randnum() {
    if [ "$#" -ne 2 ]; then
        echo "Usage: randnum <a> <b>"
        return 0
    fi
    if [ $2 -lt $1 ]; then
        echo "Upper boundary must be greater than lower!"
        return 0
    fi
    echo $((RANDOM % ($2-$1) + $1)) | bc
}

# Random string with desired length
randstring() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: randstring <len>"
        return 0
    fi

    if [ $1 -le 0 ]; then
        echo "Length must be greater than 0!"
        return 0
    fi

    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $1 | head -n 1
}

#
# =======================================================
# COLORS
#

# Restore default color setting.
# By default, set it to white color instead of actual restore.
RESTORE=$(echo -en '\033[0m')

RED=$(echo -en '\033[00;31m')
GREEN=$(echo -en '\033[00;32m')
YELLOW=$(echo -en '\033[00;33m')
BLUE=$(echo -en '\033[00;34m')
MAGENTA=$(echo -en '\033[00;35m')
PURPLE=$(echo -en '\033[00;35m')
CYAN=$(echo -en '\033[00;36m')
LIGHTGRAY=$(echo -en '\033[00;37m')
LRED=$(echo -en '\033[01;31m')
LGREEN=$(echo -en '\033[01;32m')
LYELLOW=$(echo -en '\033[01;33m')
LBLUE=$(echo -en '\033[01;34m')
LMAGENTA=$(echo -en '\033[01;35m')
LPURPLE=$(echo -en '\033[01;35m')
LCYAN=$(echo -en '\033[01;36m')
WHITE=$(echo -en '\033[01;37m')

red() { 
    echo $RED$1$RESTORE 
}
green() { 
    echo $GREEN$1$RESTORE 
}
yellow() {
 echo $YELLOW$1$RESTORE 
}
blue() {
 echo $BLUE$1$RESTORE 
}
magenta() {
 echo $MAGENTA$1$RESTORE 
}
purple() {
 echo $PURPLE$1$RESTORE 
}
cyan() {
 echo $CYAN$1$RESTORE 
}
lightgray() {
 echo $LIGHTGRAY$1$RESTORE 
}
lred() {
 echo $LRED$1$RESTORE 
}
lgreen() {
 echo $LGREEN$1$RESTORE 
}
lyellow() {
 echo $LYELLOW$1$RESTORE 
}
lblue() {
 echo $LBLUE$1$RESTORE 
}
lmagenta() {
 echo $LMAGENTA$1$RESTORE 
}
lpurple() {
 echo $LPURPLE$1$RESTORE 
}
lcyan() {
 echo $LCYAN$1$RESTORE 
}
white() {
 echo $WHITE$1$RESTORE 
}


# 
# =======================================================
# OTHER TWEAKS & HACKS
#

export HISTCONTROL=ignoredups:erasedups  # no duplicate entries
export HISTSIZE=100000                   # big big history
export HISTFILESIZE=100000               # big big history
shopt -s histappend                      # append to history, don't overwrite it

# Save and reload the history after each command finishes
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"


#
# =======================================================
# ENVIRONMENT DEPENDING
#

export ENCLIP_RECIPIENT=
export LESS='-F -R -X $LESS'
export LESSOPEN='|~/.lessfilter %s'

alias forcefullists='find ~/data/SecLists/Discovery/Web_Content/ -type f -exec sh -c "wc -l {}" \; | column -t | sort -k1,1nr | head -n 30'
defaultiface=`ip route ls | grep default | pcregrep -o1 '.+dev (\S+).+'`
alias diface=`echo $defaultiface`

function nmapscripts() {
    find /usr/share/nmap/scripts/ -exec basename {} \; | grep -i "$1" | column
}

alias bcb='~/tools/Penetration-Testing-Tools/web/burp-curl-beautifier.py'

alias mirror='wget -mkEpnp -e robots=off'
alias web1='python -m SimpleHTTPServer'
alias web2='ruby -run -ehttpd . -p8000'
alias eslintjs='eslint --no-eslintrc -c ~/.eslintrc.js .'

alias unblock_dir='sudo chmod -R 755'
alias block_dir='sudo chmod -R 700'

alias recursivegitpull='find . -mindepth 1 -maxdepth 1 -type d -print -exec git -C {} pull \;'
EOF

sed -i -r "s:~/:$ROOT_DIR/:" $ROOT_DIR/.bashrc
