## Install vscode
1) Linux: sudo snap install code --classic / sudo apt install code
2) Windows: Refer official documentation (https://code.visualstudio.com/)
3) Install Live server extension in vscode:
     * Go to extensions tab -> search "live server" -> Install extension

## Install node js
1) Linux: sudo apt install nodejs
2) Windows: https://nodejs.org/en/download/

## setup python and venv (For Linux Only)
### setup venv
1) sudo apt update
2) sudo apt install python3 python3-pip python3-venv
### Activate venv
1) mkdir myproject && cd myproject
2) python3 -m venv venv
3) source venv/bin/activate
### Install flask (continue from here for windows too: Run with administrative previleges)
1) pip install Flask
2) python -m flask --version
### Install Bandit
1) sudo snap install bandit / sudo apt install bandit: **Linux**
2) pip install bandit: **Windows**
3) bandit --version
