curl -s https://api.github.com/repos/ropnop/impacket_static_binaries/releases/latest | grep "browser_download_url.*exe" | cut -d : -f 2,3 | tr -d \" | wget -qi -
