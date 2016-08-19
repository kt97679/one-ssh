osname=$(grep -h -o -i -P 'xenserver|centos|ubuntu' /etc/*-release|head -n1|tr 'A-Z' 'a-z')
case $osname in
    ubuntu)
        pkg_version() {
            dpkg -l|grep "$1"
        }
        ;;
    centos|xenserver)
        pkg_version() {
            rpm -qa|grep "$1"
        }
        ;;
esac
