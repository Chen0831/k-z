#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: Debian/Ubuntu
#	Description: TCP-BBR
#=================================================

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

#检查系统
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
}

Set_latest_new_version(){
	echo -e "请输入 要下载安装的Linux内核版本(BBR) [ 格式: x.xx.xx ，例如: 4.10.12 ]
${Tip} 内核版本列表请去这里获取：[ http://kernel.ubuntu.com/~kernel-ppa/mainline/ ]"
	stty erase '^H' && read -p "(默认回车，自动获取最新版本):" latest_version
	[[ -z "${latest_version}" ]] && get_latest_new_version
	echo
}
get_latest_new_version(){
	echo -e "${Info} 检测内核最新版本中..."
	latest_version=$(wget -qO- "http://kernel.ubuntu.com/~kernel-ppa/mainline/" | awk -F'\"v' '/v[4-9].[0-9]*.[0-9]/{print $2}' |grep -v '\-rc'| cut -d/ -f1 | sort -V | tail -1)
	[[ -z ${latest_version} ]] && echo -e "\033[41;37m [错误] \033[0m 检测内核最新版本失败 !" && exit 1
	echo -e "${Info} 当前内核最新版本为 : ${latest_version}"
}
get_latest_version(){
	Set_latest_new_version
	bit=`uname -m`
	if [[ ${bit} == "x86_64" ]]; then
		deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
		deb_kernel_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/${deb_name}"
		deb_kernel_name="linux-image-${latest_version}-amd64.deb"
	elif [ ${bit} == "i386" ]; then
		deb_name=$(wget -qO- http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/ | grep "linux-image" | grep "generic" | awk -F'\">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
		deb_kernel_url="http://kernel.ubuntu.com/~kernel-ppa/mainline/v${latest_version}/${deb_name}"
		deb_kernel_name="linux-image-${latest_version}-i386.deb"
	else
		echo -e "${Error} 不支持 ${bit} !" && exit 1
	fi
}
#检查内核是否满足
check_deb_off(){
	get_latest_new_version
	deb_ver=`dpkg -l|grep linux-image | awk '{print $2}' | awk -F '-' '{print $3}' | grep '[4-9].[0-9]*.'`
	if [[ "${deb_ver}" != "" ]]; then
		if [[ "${deb_ver}" == "${latest_version}" ]]; then
			echo -e "${Info} 检测到 内核版本 已满足要求，继续..."
		else
			echo -e "\033[42;37m[错误]\033[0m 检测到 内核版本 不是最新版本，建议使用${Green_font_prefix} bash bbr.sh ${Font_color_suffix}来升级内核 !"
		fi
	else
		echo -e "${Error} 检测到 内核版本 不支持开启BBR，请使用${Green_font_prefix} bash bbr.sh ${Font_color_suffix}来更换最新内核 !" && exit 1
	fi
}
# 删除其余内核
del_deb(){
	deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${latest_version}" | wc -l`
	if [ "${deb_total}" > "1" ]; then
		echo -e "${Info} 检测到 ${deb_total} 个其余内核，开始卸载..."
		for((integer = 1; integer <= ${deb_total}; integer++))
		do
			deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${latest_version}" | head -${integer}`
			echo -e "${Info} 开始卸载 ${deb_del} 内核..."
			apt-get purge -y ${deb_del}
			echo -e "${Info} 卸载 ${deb_del} 内核卸载完成，继续..."
		done
		deb_total=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${latest_version}" | wc -l`
		if [ "${deb_total}" = "0" ]; then
			echo -e "${Info} 内核卸载完毕，继续..."
		else
			echo -e "${Error} 内核卸载异常，请检查 !" && exit 1
		fi
	else
		echo -e "${Error} 检测到 内核 数量不正确，请检查 !" && exit 1
	fi
}
del_deb_over(){
	del_deb
	update-grub
	echo -e "\033[42;37m[注意]\033[0m 重启VPS后，请重新运行脚本开启BBR \033[42;37m bash bbr.sh start \033[0m"
	stty erase '^H' && read -p "需要重启VPS后，才能开启BBR，是否现在重启 ? [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
		echo -e "\033[41;37m[信息]\033[0m VPS 重启中..."
		reboot
		fi
}
# 安装BBR
installbbr(){
# 系统判断
	check_sys
	if [[ ${release} != "debian" ]]; then
		if [[ ${release} != "ubuntu" ]]; then
			echo -e "${Error} 本脚本不支持当前系统 !" && exit 1
		fi
	fi
	get_latest_version
	deb_ver=`dpkg -l|grep linux-image | awk '{print $2}' | awk -F '-' '{print $3}' | grep '[4-9].[0-9]*.'`
	if [ "${deb_ver}" != "" ]; then
		if [ "${deb_ver}" == "${latest_version}" ]; then
			echo -e "${Info} 检测到 当前内核版本 已是最新版本，无需继续安装 !"
			deb_total=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${latest_version}" | wc -l`
			if [ "${deb_total}" != "0" ]; then
				echo -e "${Red_background_prefix}[信息]${Font_color_suffix} 检测到内核数量异常，存在多余内核，开始删除..."
				del_deb_over
			else
				exit 1
			fi
		else
			echo -e "${Info} 检测到 当前内核版本 不是最新版本，升级(或降级)内核..."
		fi
	else
		echo -e "${Info} 检测到 当前内核版本 不支持开启BBR，开始安装..."
		virt=`virt-what`
		if [[ ${virt} = "" ]]; then
			apt-get update && apt-get install virt-what -y
			virt=`virt-what`
		fi
		if [[ ${virt} = "openvz" ]]; then
			echo -e "${Error} BBR 不支持 OpenVZ 虚拟化 !" && exit 1
		fi
	fi
	echo "nameserver 8.8.8.8" > /etc/resolv.conf
	echo "nameserver 8.8.4.4" >> /etc/resolv.conf

	wget -O ${deb_kernel_name} "${deb_kernel_url}"
	if [ -s ${deb_kernel_name} ]; then
		echo -e "${Info} 内核文件下载成功，开始安装内核..."
		dpkg -i ${deb_kernel_name}
		rm -rf ${deb_kernel_name}
	else
		echo -e "${Error} 内核文件下载失败，请检查 !" && exit 1
	fi
	#判断内核是否安装成功
	deb_ver=`dpkg -l | grep linux-image | awk '{print $2}' | awk -F '-' '{print $3}' | grep "${latest_version}"`
	if [ "${deb_ver}" != "" ]; then
		echo -e "${Info} 检测到 内核 已安装成功，开始卸载其余内核..."
		del_deb_over
	else
		echo -e "${Error} 检测到 内核版本 安装失败，请检查 !" && exit 1
	fi
}
bbrstatus(){
	check_bbr_status_on=`sysctl net.ipv4.tcp_available_congestion_control | awk '{print $3}'`
	if [ "${check_bbr_status_on}" = "bbr" ]; then
		echo -e "${Info} 检测到 BBR 已开启 !"
		# 检查是否启动BBR
		check_bbr_status_off=`lsmod | grep bbr`
		if [ "${check_bbr_status_off}" = "" ]; then
			echo -e "${Error} 检测到 BBR 已开启但未正常启动，请检查 !"
		else
			echo -e "${Info} 检测到 BBR 已开启并已正常启动 !"
		fi
		exit 1
	fi
}
# 开启BBR
startbbr(){
	check_deb_off
	bbrstatus
	sed -i '/net\.core\.default_qdisc=fq/d' /etc/sysctl.conf
	sed -i '/net\.ipv4\.tcp_congestion_control=bbr/d' /etc/sysctl.conf

	echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	sysctl -p
	sleep 1s
	bbrstatus
	echo -e "${Error} BBR 启动失败，请检查 !"
}
# 关闭BBR
stopbbr(){
	check_deb_off
	sed -i '/net\.core\.default_qdisc=fq/d' /etc/sysctl.conf
	sed -i '/net\.ipv4\.tcp_congestion_control=bbr/d' /etc/sysctl.conf
	sysctl -p
	sleep 1s

	stty erase '^H' && read -p "需要重启VPS后，才能彻底停止BBR，是否现在重启 ? [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
		if [[ $yn == [Yy] ]]; then
		echo -e "\033[41;37m[信息]\033[0m VPS 重启中..."
		reboot
		fi
}
# 查看BBR状态
statusbbr(){
	check_deb_off
	bbrstatus
	echo -e "${Error} BBR 未开启 !"
}

action=$1
[ -z $1 ] && action=install
case "$action" in
	install|start|stop|status)
	${action}bbr
	;;
	*)
	echo "输入错误 !"
	echo "用法: { install | start | stop | status }"
	;;
esac
