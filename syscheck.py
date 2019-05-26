#!/usr/bin/env python
# -*- coding: utf-8 -*-
    
"""
This module is used for collecting and analyzing system information.
"""

from __future__ import print_function
import sys
import os
import re
import glob


class SysCheck:
    """
    Each host(or ip, or server) is considered as an instance of class SysInfo,
    because every host will apply the same process, their only difference is
    IP Address.
    """
    suffix = '.tar.gz'

    def __init__(self, ip):
        self.ip = ip
        self.extract_dir = os.path.join(self.tgz_dir, 'tmpData')
        self.data_dir = os.path.join(self.extract_dir, self.ip)

    def _format_file_content(self, fl):
        """This function is to exclude useless content in a file, used for all
        the following functions
        """
        if os.path.isfile(fl):
            try:
                formated = [
                    ln.strip() for ln in open(fl)
                    if not ln.startswith('#') and not ln.startswith('\n')
                ]
                return formated 
            except UnicodeDecodeError:
                formated = [
                    ln.strip() for ln in open(fl, encoding='gbk', errors='ignore')
                    if not ln.startswith('#') and not ln.startswith('\n')
                ]
                return formated 


    def _warn(self, res):
        return False if res == 'N/A' or '无' else True


    def chk_uid0_account(self):
        fl = os.path.join(self.data_dir, 'passwd.txt')
        lns = self._format_file_content(fl)
        if lns:
            kws = ['0', 'root']
            uid0_account = ', '.join([
                ln.split(':')[0]
                for ln in lns
                if ln.split(':')[0] != kws[1] and ln.split(':')[2] == kws[0]
            ]) or '无'
            warn = self._warn(uid0_account)
        else:
            uid0_account = ('N/A', False)

        return {'result': uid0_account, 'warn': warn}


    def chk_sudo_account(self):
        fl = os.path.join(self.data_dir, 'sudoers.txt')
        lns = self._format_file_content(fl)
        if lns:
            kws = ['ALL=', 'root']
            sudo_account = ', '.join([
                ln.split()[0]
                for ln in lns
                if kws[0] in ln and not kws[1] in ln
            ]) or 'N/A'

            warn = self._warn(sudo_account)
        else:
            sudo_account, warn = ('N/A', False)

        return {'result': sudo_account, 'warn': warn}


    def chk_umask_set(self):
        fl = os.path.join(self.data_dir, 'etc_bashrc.txt')
        kw = 'umask'
        threshold = '027'
        lns = self._format_file_content(fl)
        umask_set = [ln.split()[-1] for ln in lns if kw in ln][-1]
        f = lambda x: int(x.lstrip('0'))
        warn = True if f(umask_set) < f(threshold) else False

        return {'result': umask_set, 'warn': warn}


    def chk_bash_vulnerabilities(self):
        pt = 'CVE-\d{4}-\d{4}'
        f = lambda lns, kw: ', '.join([
            re.findall(pt, ln)[0] for ln in lns if kw in ln
        ])
        fl = os.path.join(self.data_dir, 'bash.txt')
        kw = 'vulnerable'
        lns = self._format_file_content(fl)
        bash_vulnerabilities= f(lns, kw) or '无'

        warn = self._warn(bash_vulnerabilities)

        return {'result': bash_vulnerabilities, 'warn': warn}


    def chk_glibc_vulnerabilities(self):
        pt = 'CVE-\d{4}-\d{4}'
        f = lambda lns, kw: ', '.join([
            re.findall(pt, ln)[0] for ln in lns if kw in ln
        ])

        fl = os.path.join(self.data_dir, 'ghost.txt')
        kw = 'CVE'
        lns = self._format_file_content(fl)
        glibc_vulnerabilities= f(lns, kw) or '无'

        warn = self._warn(glibc_vulnerabilities)

        return {'result': glibc_vulnerabilities, 'warn': warn}


    def chk_openssl_vulnerabilities(self):
        fl = os.path.join(self.data_dir, 'rpm_-qa.txt')
        try:
            content = open(fl).read()
        except UnicodeDecodeError:
            content = open(fl, encoding='gbk', errors='ignore').read()
        cves = ['CVE_2016_0800', 'CVE_2014_8176']
        pt1 = 'openssl-[0-9].*'
        pt2 = '.*-([0-9]+)\.el([0-9])'
        rpm = re.findall(pt1, content)[0]
        if rpm:
            t = re.findall(pt2, rpm)[0]
            rpm_version = int(t[0])
            os_version = int(t[1])
            if rpm_version < 39 and os_version == 5:
                openssl_vulnerabilities = cves[0]
            elif rpm_version < 30 and os_version == 6:
                openssl_vulnerabilities = ', '.join(cves)
            elif 30 < rpm_version < 42 and os_version == 6:
                openssl_vulnerabilities = cves[0]
            elif rpm_version < 42 and os_version == 7:
                openssl_vulnerabilities = ', '.join(cves)
            elif 42 < rpm_version < 51 and os_version == 7:
                openssl_vulnerabilities = cves[0]
            else:
                openssl_vulnerabilities = '无'
        else:    # don't support SUSE
            openssl_vulnerabilities = 'N/A'

        warn = self._warn(openssl_vulnerabilities)

        return {'result': openssl_vulnerabilities, 'warn': warn}
        

    def chk_openssh_vulnerabilities(self):
        fl = os.path.join(self.data_dir, 'rpm_-qa.txt')
        try:
            content = open(fl).read()
        except UnicodeDecodeError:
            content = open(fl, encoding='gbk', errors='ignore').read()
        cves = ['CVE_2015_5600', 'CVE_2016_0778']
        pt1 = 'openssh-server-[0-9].*'
        #pt2 = '.*-([0-9]+)\.el([0-9])'
        pt2 = '.*-([0-9]+)\.([0-9]\.)?el([0-9])'
        rpm = re.findall(pt1, content)[0]
        if rpm:
            t = re.findall(pt2, rpm)[0]
            rpm_version = int(t[0])
            os_version = int(t[-1])
            if os_version == 5:
                openssh_vulnerabilities = 'N/A'
            elif rpm_version < 114 and os_version == 6:
                openssh_vulnerabilities = cves[0]
            elif rpm_version < 22 and os_version == 7:
                openssh_vulnerabilities = ', '.join(cves)
            elif rpm_version == 22 and os_version == 7:
                openssh_vulnerabilities = cves[0]
            else:
                openssh_vulnerabilities = '无'
        else:    # don't support SUSE
            openssh_vulnerabilities = 'N/A'

        warn = self._warn(openssh_vulnerabilities)

        return {'result': openssh_vulnerabilities, 'warn': warn}
        

    def chk_ntp_vulnerabilities(self):
        fl = os.path.join(self.data_dir, 'rpm_-qa.txt')
        try:
            content = open(fl).read()
        except UnicodeDecodeError:
            content = open(fl, encoding='gbk', errors='ignore').read()
        cves = ['CVE_2014_9293', 'CVE_2014_9294', 'CVE_2014_9295']
        pt1 = 'ntp-[0-9].*'
        pt2 = '.*-([0-9]+)\.el([0-9])'
        try:
            rpm = re.findall(pt1, content)[0]
        except IndexError:
            ntp_vulnerabilities, warn = ('N/A', False)
            return {'result': ntp_vulnerabilities, 'warn': warn}
        t = re.findall(pt2, rpm)[0]
        rpm_version = int(t[0])
        os_version = int(t[1])
        if rpm_version < 18 and os_version == 5:
            ntp_vulnerabilities = ', '.join(cves)
        elif rpm_version == 1 and os_version == 6:
            ntp_vulnerabilities = ', '.join(cves)
        elif rpm_version < 19 and os_version == 7:
            ntp_vulnerabilities = ', '.join(cves)
        else:
            ntp_vulnerabilities = '无'

        # do not support SUSE
        ntp_vulnerabilities = 'N/A'

        warn = self._warn(ntp_vulnerabilities)

        return {'result': ntp_vulnerabilities, 'warn': warn}
        

    def chk_remote_timeout(self):
        fl = os.path.join(self.data_dir, 'etc_profile.txt')
        kw = 'TMOUT'
        lns = self._format_file_content(fl)
        res = [ln.split('=')[-1].strip() for ln in lns if kw in ln]
        remote_timeout = res[0] if res else 'N/A'

        warn = self._warn(remote_timeout)

        return {'result': remote_timeout, 'warn': warn}


    def chk_core_dump(self):
        fl = os.path.join(self.data_dir, 'limits.conf.txt')
        kw = 'core'
        lns = self._format_file_content(fl)
        fl1 = os.path.join(self.data_dir, 'limits.d/90-nproc.conf')
        if os.path.isfile(fl1):
            extra = self._format_file_content(fl1)
            if extra:
                lns.extend(extra)

        l = [ln for ln in lns if kw in ln]
        core_dump, warn = ('已启用', False) if l else ('未启用', True)

        return {'result': core_dump, 'warn': warn}


    def chk_selinux_status(self):
        fl = os.path.join(self.data_dir, 'selinux.txt')
        lns = self._format_file_content(fl)
        kw = 'SELINUX=disabled'
        l = [ln for ln in lns if kw in ln]
        selinux_status, warn = ('未启用', False) if l else ('已启用', True)

        return {'result': selinux_status, 'warn': warn}


    def chk_firewall_status(self):
        fl1 = os.path.join(self.data_dir, 'iptables_-nL.txt')
        threshold1 = [
            'Chain INPUT (policy ACCEPT)',
            'target     prot opt source               destination',
            '',
            'Chain FORWARD (policy ACCEPT)',
            'target     prot opt source               destination',
            '',
            'Chain OUTPUT (policy ACCEPT)',
            'target     prot opt source               destination'
        ]
        fl2= os.path.join(self.data_dir, 'susefirewall2_status.txt')
        threshold2 = 'SuSEfirewall2: SuSEfirewall2 not active'

        if os.path.isfile(fl1):
            lns = self._format_file_content(fl1)
            if not threshold1 == lns:
                firewall_status, warn = ('已启用', True) 
            else:
                firewall_status, warn = ('未启用', False) 
        elif os.path.isfile(fl2):    # for SUSE
            lns = self._format_file_content(fl2)
            if not threshold2 == lns:
                firewall_status, warn = ('已启用', True) 
            else:
                firewall_status, warn = ('未启用', False) 
        else:
            firewall_status, warn = ('N/A', False) 

        return {'result': firewall_status, 'warn': warn}


    def chk_ip_disguise(self):
        fl = os.path.join(self.data_dir, 'host.conf.txt')
        kws = ['nospoof', 'on']
        lns = self._format_file_content(fl)
        if lns:
            l = [ln.split() for ln in lns if kws[0] in ln]
            if l:
                if kws[1] in l:
                    ip_disguise, warn = ('未启用', False)
                else:
                     ip_disguise, warn = ('已启用', True) 
            else:
                 ip_disguise, warn = ('N/A', False) 
        else:
            ip_disguise, warn = ('N/A', False) 

        return {'result': ip_disguise, 'warn': warn}


    def chk_ip_multi(self):
        fl = os.path.join(self.data_dir, 'host.conf.txt')
        kws = ['multi', 'off', 'on']
        lns = self._format_file_content(fl)
        if lns:
            l = [ln.split() for ln in lns if kws[0] in ln]
            if l:
                if kws[1] in l:
                    ip_multi, warn = ('未启用', False)
                elif kws[2] in l:
                     ip_multi, warn = ('已启用', True) 
                else:
                     ip_multi, warn = ('N/A', False) 
            else:
                 ip_multi, warn = ('N/A', False) 
        else:
            ip_multi, warn = ('N/A', False) 

        return {'result': ip_multi, 'warn': warn}


    def chk_ip_forward(self):
        fl = os.path.join(self.data_dir, 'sysctl_-a.txt')
        kw = 'net.ipv4.ip_forward '    # ip_forward 后面加了空格，因rhel7有重复
        lns = self._format_file_content(fl)
        if lns:
            n = [int(ln.split('=')[-1].strip()) for ln in lns if kw in ln][0]
            if n == 0:
                ip_forward, warn = ('未启用', False)
            elif n == 1:
                ip_forward, warn = ('已启用', True) 
            else:
                ip_forward, warn = ('N/A', False) 
        else:
            ip_forward, warn = ('N/A', False) 

        return {'result': ip_forward, 'warn': warn}


    def chk_icmp_accept_redirect(self):
        fl = os.path.join(self.data_dir, 'sysctl_-a.txt')
        kws = ['all.accept_redirect', 'default.accept_redirect']
        lns = self._format_file_content(fl)
        if lns:
            n = [
                int(ln.split('=')[-1].strip())
                for ln in lns if any(kw in ln for kw in kws)
            ]

            if 1 in n:
                icmp_accept_redirect, warn = ('已启用', True) 
            else:
                icmp_accept_redirect, warn = ('未启用', False)
        else:
            icmp_accept_redirect, warn = ('N/A', False)

        return {'result': icmp_accept_redirect, 'warn': warn}


    def chk_icmp_send_redirect(self):
        fl = os.path.join(self.data_dir, 'sysctl_-a.txt')
        kws = ['all.send_redirect', 'default.send_redirect']
        lns = self._format_file_content(fl)
        if lns:
            n = [
                int(ln.split('=')[-1].strip())
                for ln in lns if any(kw in ln for kw in kws)
            ]

            if 1 in n:
                icmp_send_redirect, warn = ('已启用', True) 
            else:
                icmp_send_redirect, warn = ('未启用', False)
        else:
            icmp_send_redirect, warn = ('N/A', False)

        return {'result': icmp_send_redirect, 'warn': warn}


    def chk_password_max_day(self):
        fl = os.path.join(self.data_dir, 'login.defs.txt')
        kw = 'PASS_MAX_DAYS'
        lns = self._format_file_content(fl)

        PASS_MAX_DAYS = [ln.split()[-1] for ln in lns if kw in ln][0]

        warn = True if int(PASS_MAX_DAYS) > 90 else False

        return {'result': PASS_MAX_DAYS, 'warn': warn}


    def chk_password_min_day(self):
        fl = os.path.join(self.data_dir, 'login.defs.txt')
        kw = 'PASS_MIN_DAYS'
        lns = self._format_file_content(fl)

        PASS_MIN_DAYS = [ln.split()[-1] for ln in lns if kw in ln][0]

        warn = True if int(PASS_MIN_DAYS) < 7 else False

        return {'result': PASS_MIN_DAYS, 'warn': warn}


    def chk_password_min_length(self):
        fl = os.path.join(self.data_dir, 'login.defs.txt')
        kw = 'PASS_MIN_LEN'
        lns = self._format_file_content(fl)

        PASS_MIN_LEN = [ln.split()[-1] for ln in lns if kw in ln][0]

        warn = True if int(PASS_MIN_LEN) < 8 else False

        return {'result': PASS_MIN_LEN, 'warn': warn}


    def chk_password_warn_day(self):
        fl = os.path.join(self.data_dir, 'login.defs.txt')
        kw = 'PASS_WARN_AGE'
        lns = self._format_file_content(fl)

        PASS_WARN_AGE = [ln.split()[-1] for ln in lns if kw in ln][0]

        warn = True if int(PASS_WARN_AGE) < 7 else False

        return {'result': PASS_WARN_AGE, 'warn': warn}


    def chk_password_complexity(self):
        fl = os.path.join(self.data_dir, 'system-auth.txt')
        kws = ['pam_cracklib.so', 'dcredit', 'lcredit', 'ucredit', 'ocredit']
        lns = self._format_file_content(fl)

        res = [ln for ln in lns if any(kw in ln for kw in kws[1:])]

        if res:
            password_complexity, warn = ('已启用', False)
        else:
            password_complexity, warn = ('未启用', True)

        return {'result': password_complexity, 'warn': warn}


    def chk_password_rem_times(self):
        fl = os.path.join(self.data_dir, 'system-auth.txt')
        kw = 'remember='
        pt = 'remember=([0-9]+)'
        lns = self._format_file_content(fl)

        l = [re.findall(pt, ln)[0] for ln in lns if kw in ln]

        if l:
            if int(l[0]) < 5:
                password_rem_times, warn = ('已配置, ' + l[0] + '次', True)
            else:
                password_rem_times, warn = ('已配置, ' + l[0] + '次', False)
        else:
            password_rem_times, warn = ('未启用', True)

        return {'result': password_rem_times, 'warn': warn}


    def chk_password_try_times(self):
        fl = os.path.join(self.data_dir, 'system-auth.txt')
        kw = 'deny='
        pt = 'deny=([0-9]+)'
        lns = self._format_file_content(fl)

        l = [re.findall(pt, ln)[0] for ln in lns if kw in ln]

        if l:
            if int(l[0]) < 3:
                password_try_times, warn = ('已配置, ' + l[0] + '次', True)
            else:
                password_try_times, warn = ('已配置, ' + l[0] + '次', False)
        else:
            password_try_times, warn = ('未启用', True)

        return {'result': password_try_times, 'warn': warn}


    def chk_password_lock_time(self):
        fl = os.path.join(self.data_dir, 'system-auth.txt')
        kw = 'unlock_time='
        pt = 'unlock_time=([0-9]+)'
        lns = self._format_file_content(fl)

        l = [re.findall(pt, ln)[0] for ln in lns if kw in ln]

        if l:
            if int(l[0]) < 600:
                password_lock_time, warn = ('已配置, ' + l[0], True)
            else:
                password_lock_time, warn = ('已配置, ' + l[0], False)
        else:
            password_lock_time, warn = ('未启用', True)

        return {'result': password_lock_time, 'warn': warn}


    def chk_GSSAPIAuthentication(self):
        fl = os.path.join(self.data_dir, 'sshd_config.txt')
        kws = ['GSSAPIAuthentication', 'yes']
        lns = self._format_file_content(fl)

        res = [ln for ln in lns if ln.split() == kws]

        if res:
            GSSAPIAuthentication, warn = ('已启用', True)
        else:
            GSSAPIAuthentication, warn = ('未启用', False)

        return {'result': GSSAPIAuthentication, 'warn': warn}


    def chk_GSSAPICleanupCredentials(self):
        fl = os.path.join(self.data_dir, 'sshd_config.txt')
        kws = ['GSSAPICleanupCredentials', 'yes']
        lns = self._format_file_content(fl)

        res = [ln for ln in lns if ln.split() == kws]

        if res:
            GSSAPICleanupCredentials, warn = ('已启用', True)
        else:
            GSSAPICleanupCredentials, warn = ('未启用', False)

        return {'result': GSSAPICleanupCredentials, 'warn': warn}


    def chk_openssh_protocol(self):
        fl = os.path.join(self.data_dir, 'sshd_config.txt')
        kws = ['Protocol', '2']
        lns = self._format_file_content(fl)

        res = [ln for ln in lns if kws[0] in ln]

        if res:
            if res[0][-1] == '2':
                openssh_protocol, warn = ('协议' + res[0].split()[-1], False)
            else:
                openssh_protocol, warn = ('协议' + res[0].split()[-1], True)
        else:
            openssh_protocol, warn = ('协议2', False)

        return {'result': openssh_protocol, 'warn': warn}


    def chk_root_remote(self):
        fl = os.path.join(self.data_dir, 'sshd_config.txt')
        kws = ['PermitRootLogin', 'no']
        lns = self._format_file_content(fl)

        res = [ln for ln in lns if ln.split() == kws]

        if res:
            root_remote, warn = ('未启用', False)
        else:
            root_remote, warn = ('已启用', True)

        return {'result': root_remote, 'warn': warn}


    def chk_openssh_x11(self):
        fl = os.path.join(self.data_dir, 'sshd_config.txt')
        kws = ['X11Forwarding', 'yes']
        lns = self._format_file_content(fl)

        res = [ln for ln in lns if ln.split() == kws]

        if res:
            openssh_x11, warn = ('已启用', True)
        else:
            openssh_x11, warn = ('未启用', False)

        return {'result': openssh_x11, 'warn': warn}


    def chk_ntp_set(self):
        # check ntp.conf
        kws = 'server ', 'pool.ntp.org'
        fl1 = os.path.join(self.data_dir, 'ntp.conf.txt')
        lns1 = self._format_file_content(fl1)
        if lns1:
            ntp_configured = [
                ln for ln in lns1
                if ln.startswith(kws[0]) and kws[1] not in ln
            ]
        else:
            ntp_configured = []

        # check crontab for ntpdate
        kw2 = 'ntpdate '
        fl2 = os.path.join(self.data_dir, 'crontab_-l.txt')
        lns2 = self._format_file_content(fl2)
        ntpdate_configured = []
        if lns2:
            ntpdate_configured = [ln for ln in lns2 if kw2 in ln]

        fl3 = os.path.join(self.data_dir, 'etc_crontab.txt')
        lns3 = self._format_file_content(fl3)
        if lns3:
            ntpdate_configured.extend([ln for ln in lns3 if kw2 in ln])

        # check service ntpd status
        kw3 = 'ntpd (pid'
        fl4 = os.path.join(self.data_dir, 'service_--status-all.txt')
        lns4 = self._format_file_content(fl4)
        if lns4:
            ntpd_running = [ln for ln in lns4 if kw3 in ln]

        # check chronyd for rhel7, will be added later.

        if ntp_configured and ntpd_running:
            ntp_set, warn = ('已连接ntp服务器: ' + ntp_configured[0].split()[1], False)
        elif ntpdate_configured and not ntpd_running:
            ntp_set, warn = ('已启用, ' + ntpdate_configured[0], False)
        else:
            ntp_set, warn = ('未启用', True)

        return {'result': ntp_set, 'warn': warn}


    def chk_lvm_set(self):
        fl = os.path.join(self.data_dir, 'lvs.txt')
        if os.path.isfile(fl):
            lvm_set, warn = ('已启用', False) 
        else:
            lvm_set, warn = ('未启用', True) 

        return {'result': lvm_set, 'warn': warn}


    def chk_run_level(self):
        fl = os.path.join(self.data_dir, 'runlevel.txt')
        try:
            res = open(fl).readline().split()[-1]
        except UnicodeDecodeError:
            res = open(fl, encoding='gbk', errors='ignore').readline().split()[-1]

        run_level, warn = (res, False) if res == '3' else (res, True)

        return {'result': run_level, 'warn': warn}


    def chk_remote_logging(self):
        kw = '@@'
        fl1 = os.path.join(self.data_dir, 'syslog.conf.txt')
        fl2 = os.path.join(self.data_dir, 'rsyslog.conf.txt')
        if os.path.isfile(fl1):
            lns1 = self._format_file_content(fl1)
            res1 = [ln for ln in lns1 if kw in ln]
            if res1:
                remote_logging, warn = ('已启用, ' + res[0], False) 
            else:
                remote_logging, warn = ('未启用', True) 
        elif os.path.isfile(fl2):
            lns2 = self._format_file_content(fl2)
            res2 = [ln for ln in lns2 if kw in ln]
            if res2:
                remote_logging, warn = ('已启用, ' + res[0], False) 
            else:
                remote_logging, warn = ('未启用', True) 
        else:
            remote_logging, warn = ('N/A', True) 

        return {'result': remote_logging, 'warn': warn}


    def chk_sys_load_info(self):
        """Check last 15mins sysload is over (3 * total number of cpu cores)"""
        fl1 = os.path.join(self.data_dir, 'uptime.txt')
        try:
            sys_load = open(fl1).readline().split()[-1]
        except UnicodeDecodeError:
            sys_load = open(fl1, encoding='gbk', errors='ignore').readline().split()[-1]

        fl2 = os.path.join(self.data_dir, 'cpuinfo.txt')

        try:
            sys_load = open(fl1).readline().split()[-1]
        except UnicodeDecodeError:
            sys_load = open(fl1, encoding='gbk', errors='ignore').readline().split()[-1]

        lns = open(fl2).read()
        cpu_num = lns.count('processor')
        threshold = cpu_num * 3

        if float(sys_load) > threshold:
            sys_load_info = '负载值: ' + sys_load + ', ' + 'CPU核心数: ' + str(cpu_num)
            warn = True
        else:
            sys_load_info = '负载值: ' + sys_load + ', ' + 'CPU核心数: ' + str(cpu_num)
            warn = False

        return {'result': sys_load_info, 'warn': warn}


    def chk_swap_use_status(self):
        fl = os.path.join(self.data_dir, 'free_-m.txt')
        lns = self._format_file_content(fl)
        template = (
            '<table class=\"new_table\">'
            '<tr>'
            '<th>swap总量</th>'
            '<th>已用swap</th>'
            '<th>空闲swap</th>'
            '<th>swap使用率%%</th>'
            '</tr>'
            '<tr>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '</tr>'
            '</table>'
        )

        threshold = 30

        swap_total = int(lns[-1].split()[1])
        swap_used = int(lns[-1].split()[2])
        swap_free = lns[-1].split()[3]
        swap_usage = round(swap_used / swap_total, 2) * 100   # to %
        
        warn = True if swap_usage > threshold else False 

        swap_total = '%s MB' % str(swap_total)
        swap_used = '%s MB' % str(swap_used)
        swap_free = '%s MB' % str(swap_free)
        swap_usage = '%s%%' % str(swap_usage)
        swap_use_status = template % (
            swap_total,
            swap_used,
            swap_free,
            swap_usage
        )

        return {'result': swap_use_status, 'warn': warn}


    def _chk_space(self, fl, main_template, sub_template):
        """This function is for the following chk_disk_use_status and
        chk_inode_use_status, check if useage is over threshold
        """
        threshold = 90
        kws = ['sr0', '.iso', 'tmpfs']
        lns = self._format_file_content(fl)
        if lns:
            lns = [
                tuple(ln.split())
                for ln in lns
                if not any(kw in ln for kw in kws)
            ]

            l = []
            disks = []
            for tp in lns[1:]:
                s = sub_template % tp
                disks.append(s)
                used = tp[-2][:-1]      # without %
                disk = tp[0]
                if not any(kw in disk for kw in kws) and float(used) >= threshold:
                    l.append(tp)

            res = main_template % ''.join(disks)
            warn = True if l else False
        else:
            res, warn = ('N/A', False)

        return {'result': res, 'warn': warn}


    def chk_disk_use_status(self):
        fl = os.path.join(self.data_dir, 'df_-hP.txt')
        main_template = (
            '<table class=\"new_table\">'
            '<tr>'
            '<th>Filesystem</th>'
            '<th>Size</th>'
            '<th>Used</th>'
            '<th>Avail</th>'
            '<th>Use%%</th>'
            '<th>Mounted on</th>'
            '</tr>'
            '%s'
            '</table>'
        )
        sub_template = (
            '<tr>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<tr>'
        )

        return self._chk_space(
            fl,
            main_template,
            sub_template
        )


    def chk_inode_use_status(self):
        fl = os.path.join(self.data_dir, 'df_-hiTP.txt')
        main_template = (
            '<table class=\"new_table\">'
            '<tr>'
            '<th>Filesystem</th>'
            '<th>Type</th>'
            '<th>Inodes</th>'
            '<th>IUsed</th>'
            '<th>IFree</th>'
            '<th>IUse%%</th>'
            '<th>Mounted on</th>'
            '</tr>'
            '%s'
            '</table>'
        )
        sub_template = (
            '<tr>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<tr>'
        )

        return self._chk_space(
            fl,
            main_template,
            sub_template
        )


    def chk_login_failed_times(self):
        """Based on record for last 3 months', check all consecutive bad
        logins which is more than 5 times
        """
        threshold = 5
        fl = os.path.join(self.data_dir, 'lastb3.txt')
        lns = self._format_file_content(fl)
        if lns:
            all_users = [ln.split()[0] for ln in lns]
            uniq_users = set(all_users)
            lastb_all = {
                user: all_users.count(user)
                for user in uniq_users
                if all_users.count(user) >= threshold
            }

            kw = lambda x: (all_users[x], lns[x].split()[-6:-4])
            count = 1
            lastb_daily = {}
            for i in range(1, len(lns)):
                if kw(i-1) == kw(i):
                    count += 1
                else:
                    (user, day) = kw(i-1)
                    day = ' '.join(day)     # eg. "Mar 19"
                    if count >= threshold:
                        if user not in lastb_daily:
                            lastb_daily[user] = [{'day': day, 'count': count}]
                            count = 1
                            continue
                        else:
                            lastb_daily[user].append({'day': day, 'count': count})
                            count = 1
                            continue
                    else:
                        count = 1
                        continue

            main_template = (
                '<table class=\"new_table\">'
                '<tr>'
                '<th>登陆用户</th>'
                '<th>登陆日期</th>'
                '<th>当天登陆失败次数</th>'
                '<th>过去90天登陆失败次数</th>'
                '</tr>'
                '%s'
                '</table>'
            )
            sub_template = (
                '<tr>'
                '<td>%s</td>'
                '<td>%s</td>'
                '<td>%s</td>'
                '<td>%s</td>'
                '<tr>'
            )

            l = []
            if lastb_daily:
                # 遍历每个用户的登陆情况
                for user in lastb_daily:
                    # 单个用户可能有多天记录: [{'count': 5, 'day': 'Jul 24'}, ...]
                    for d in lastb_daily[user]:
                        tp = (
                            user,
                            d['day'],
                            d['count'],
                            lastb_all[user]
                        )
                        l.append(tp)

                res = []
                for tp in l:
                    s = sub_template % tp
                    res.append(s)
                login_failed_times, warn = (main_template % ''.join(res), True)
            else:
                login_failed_times, warn = ('无', False)
        else:
            login_failed_times, warn = ('N/A', False)

        return {'result': login_failed_times, 'warn': warn}


    def chk_zombie_process(self):
        """Check if any zombie processes"""
        threshold = 'Z'
        fl = os.path.join(self.data_dir, 'ps_-A_-o_ppidstat.txt')
        lns = self._format_file_content(fl)

        main_template = (
            '<table class=\"new_table\">'
            '<tr>'
            '<th>STAT</th>'
            '<th>PPID</th>'
            '<th>PID</th>'
            '<th>CMD</th>'
            '</tr>'
            '%s'
            '</table>'
        )
        sub_template = (
            '<tr>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<tr>'
        )

        l = [ln for ln in lns if ln.startswith(threshold)]
        if l:
            res = []
            zombies = [tuple(ln.split()) for ln in l]
            for tp in zombies:
                l1 = list(tp[:3])
                l2 = list(tp[3:])
                CMD = ' '.join(l2)    # 因CMD可能会包含空格，需整合成一个字符串
                l1.append(CMD)
                tp = tuple(l1)
                s = sub_template % tp
                res.append(s)
            zombie_process, warn = (main_template % ''.join(res), True)
        else:
            zombie_process, warn = ('无', False)

        return {'result': zombie_process, 'warn': warn}


    def chk_errlog(self):
        fl = os.path.join(self.data_dir, 'messages.txt')
        file_size_mb = int(os.path.getsize(fl) / 1024 / 1024)
        if file_size_mb > 500:
            return {'result': 'N/A', 'warn': True}
        else:
            kws = [' error', ' fail', ' not', ' warn']
            lns = self._format_file_content(fl)
    
            # get the line indexes of error lines
            indexes = [
                index for index, ln in enumerate(lns)
                if any(kw in ln.casefold() for kw in kws)
            ]
            err_num = len(indexes)
    
            # get parts of err logs, skip error logs included in last part
            if indexes:
                ## method one:
                #keep = [indexes[0]]
                #mark = 0
                #for i in range(1, len(indexes)):
                #    if indexes[i] - indexes[mark] > 9:
                #        keep.append(indexes[i])
                #        mark = i
                #    else:
                #        continue

                ## method two:
                keep = []
                mark = 0
                for num in indexes:
                    if num > mark:
                        keep.append(num)
                        mark = num + 9
            
                err_parts = [
                    ''.join(lns[index-10:index+10])
                    for index in keep
                ]
                errlog = {'err_num': err_num, 'err_parts': err_parts}
                warn = True
            else:
                errlog = '无'
                warn = False
    
            return {'result': errlog, 'warn': warn}


    def chk_dmesg_err_num(self):
        fl = os.path.join(self.data_dir, 'dmesg.txt')
        kws = ['error', 'fail', 'not', 'warn']
        try:
            res = [
                ln for ln in open(fl)
                if any(kw in ln for kw in kws)
            ]
        except UnicodeDecodeError:
            res = [
                ln for ln in open(fl, encoding='gbk', errors='ignore')
                if any(kw in ln for kw in kws)
            ]

        if res:
            dmesg_err_num, warn = (len(res), True)
        else:
            dmesg_err_num, warn = ('无', False)

        return {'result': dmesg_err_num, 'warn': warn}


def run(tgz_dir):
    SysCheck.tgz_dir = tgz_dir
    iplist = [
        os.path.basename(tgz).split(SysCheck.suffix)[0]
        for tgz in glob.glob(SysCheck.tgz_dir + '/*' + SysCheck.suffix)
    ]
    exec_methods = [
        'chk_uid0_account',
        'chk_sudo_account',
        'chk_umask_set',
        'chk_bash_vulnerabilities',
        'chk_glibc_vulnerabilities',
        'chk_openssl_vulnerabilities',
        'chk_openssh_vulnerabilities',
        'chk_ntp_vulnerabilities',
        'chk_remote_timeout',
        'chk_core_dump',
        'chk_selinux_status',
        'chk_firewall_status',
        'chk_ip_disguise',
        'chk_ip_multi',
        'chk_ip_forward',
        'chk_icmp_accept_redirect',
        'chk_icmp_send_redirect',
        'chk_password_max_day',
        'chk_password_min_day',
        'chk_password_min_length',
        'chk_password_warn_day',
        'chk_password_complexity',
        'chk_password_rem_times',
        'chk_password_try_times',
        'chk_password_lock_time',
        'chk_GSSAPIAuthentication',
        'chk_GSSAPICleanupCredentials',
        'chk_openssh_protocol',
        'chk_root_remote',
        'chk_openssh_x11',
        'chk_ntp_set',
        'chk_lvm_set',
        'chk_run_level',
        'chk_remote_logging',
        'chk_sys_load_info',
        'chk_swap_use_status',
        'chk_disk_use_status',
        'chk_inode_use_status',
        'chk_login_failed_times',
        'chk_zombie_process',
        'chk_errlog',
        'chk_dmesg_err_num'
    ]

    data = {}
    for ip in iplist:
        syscheck = SysCheck(ip)
        data[ip] = {}
        for method in exec_methods:
            item_name = method.split('chk_')[-1]
            data[ip][item_name] = getattr(syscheck, method)()
    """
    Structure of data dict, data =
        {
            'ip1': {
                'item_name1': {
                    'result': value, 'warn': value,
                }
                'item_name2': {
                    'result': value, 'warn': value,
                }
                ...
            },
            'ip2': {
                'item_name1': {
                    'result': value, 'warn': value,
                }
                'item_name2': {
                    'result': value, 'warn': value,
                }
                ...
            },
            ...
        }
    """
    return data
