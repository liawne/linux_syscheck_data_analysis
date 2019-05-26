#!/usr/bin/env python
# -*- coding: utf-8 -*-
    
"""
This module is used for collecting system information that don't need analysis.
"""

from __future__ import print_function
import sys
import os
import re
import glob
import tarfile


class SysInfo:
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

    def _extract(self):
        tgz = os.path.join(self.tgz_dir, self.ip + self.suffix)
        tf = tarfile.open(tgz)
        tf.extractall(self.extract_dir)
        # chmod -R 755 data_dir in case some file do not have 'x'
        os.system('chmod -R 755 ' + os.path.join(self.extract_dir, self.ip))


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


    def get_check_time(self):
        fl = os.path.join(self.data_dir, 'date.txt')
        lns = self._format_file_content(fl)
        check_time = lns or 'N/A'

        return {'check_time': check_time}


    def get_hostname(self):
        fl = os.path.join(self.data_dir, 'hostname.txt')
        lns = self._format_file_content(fl)
        hostname = lns[0] or 'N/A'

        return {'hostname': hostname}


    def get_os(self):
        fl = os.path.join(self.data_dir, 'lsb_release_-a.txt')
        lns = self._format_file_content(fl)
        if lns:
            os_version = lns[2].split('\t')[1]
        else:
            os_version = 'N/A'

        return {'operating_system': os_version}


    def get_cpu_usage(self):    # in %
        fl = os.path.join(self.data_dir, 'top.txt')
        lns = self._format_file_content(fl)
        cpu_idle = lns[2].split(',')[3][:-3]
        cpu_usage = round(100 - float(cpu_idle), 2)
        cpu_usage = '%s%%' % cpu_usage

        return {'cpu_usage': cpu_usage}
        

    def get_uptime(self):
        fl = os.path.join(self.data_dir, 'uptime.txt')
        lns = self._format_file_content(fl)
        if lns:
            fields = lns[0].split(',')
            # sys_load_info_15
            sys_load_info_15 = fields[-1].strip()
            # sys_running_time
            sys_running_time = ' '.join(fields[0].split()[-2:])
        else:
            sys_load_info_15 = sys_running_time = 'N/A'

        return {
            'sys_load_info_15': sys_load_info_15,
            'sys_running_time': sys_running_time
        }


    def get_mem(self):    # in %
        fl = os.path.join(self.data_dir, 'free_-m.txt')
        lns = self._format_file_content(fl)

        # template for html, same for all following ones.
        template = (
            '<table class=\"new_table\">'
            '<tr>'
            '<th>内存总量</th>'
            '<th>已用内存</th>'
            '<th>空闲内存</th>'
            '<th>内存使用率</th>'
            '</tr>'
            '<tr>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '</tr>'
            '</table>'
        )

        mem_total = int(lns[1].split()[1])

        # mem_status
        if len(lns) == 3:       # RHEL 7
            mem_used = int(lns[1].split()[2])
            mem_free = lns[1].split()[3]
            mem_usage = round(mem_used / mem_total, 2) * 100    # to %
            
            mem_total = '%s MB' % str(mem_total)
            mem_used = '%s MB' % str(mem_used)
            mem_usage = '%s%%' % str(mem_usage)
            mem_use_status = template % (
                mem_total,
                mem_used,
                mem_free,
                mem_usage
            )
        else:                   # RHEL 5, 6, SUSE
            mem_used = int(lns[2].split()[2]) 
            mem_free = int(lns[2].split()[3]) 
            mem_usage = round(mem_used / mem_total, 2) * 100    # to %

            mem_total = '%s MB' % str(mem_total)
            mem_used = '%s MB' % str(mem_used)
            mem_free = '%s MB' % str(mem_free)
            mem_usage = '%s%%' % str(mem_usage)
            mem_use_status = template % (
                mem_total,
                mem_used,
                mem_free,
                mem_usage
            )

        # swap_status
        swap_total = int(lns[-1].split()[1])
        swap_used = int(lns[-1].split()[2]) 
        swap_free = int(lns[-1].split()[3]) 
        swap_usage = round(swap_used / swap_total, 2) * 100     # to %

        swap_total = '%s MB' % str(swap_total)
        swap_used = '%s MB' % str(swap_used)
        swap_free = '%s MB' % str(swap_free)
        swap_usage = '%s%%' % str(swap_usage)

        return {
            'mem_usage': mem_usage,
            'mem_use_status': mem_use_status,
            'mem_free': mem_free,
            'swap_usage': swap_usage,
            'swap_free': swap_free
        }
        

    def get_shell_account(self):
        fl = os.path.join(self.data_dir, 'passwd.txt')
        kw = 'bash\n'
        lns = self._format_file_content(fl)
        if lns:
            shell_account = ', '.join([
                ln.split(':')[0]
                for ln in lns
                if ln.split('/')[-1] == kw
            ])
        else:
            shell_account = 'N/A'

        return {'shell_account': shell_account}


    def get_product_name(self):
        fl = os.path.join(self.data_dir, 'dmidecode.txt')
        lns = self._format_file_content(fl)
        if lns:
            kw = 'Product Name'
            product_name = [
                ln for ln in lns
                if kw in ln
            ][0].split(':')[-1].strip()
        else:
            product_name = 'N/A'

        return {'product_name': product_name}


    def get_cpu_info(self):
        fl = os.path.join(self.data_dir, 'cpuinfo.txt')
        lns = self._format_file_content(fl)
        if lns:
            kw = 'model name'
            template = '<table class=\"new_table\"><tr><td>%s</td></tr></table>'
            model_name = [
                ' '.join(ln.split(':')[1].split())
                for ln in lns if kw in ln
            ]
            model_name = ', '.join(list(set(model_name)))
            cpu_info = template % model_name
        else:
            cpu_info = 'N/A'

        return {'cpu_info': cpu_info}


    def get_disk_info(self):
        fl = os.path.join(self.data_dir, 'fdisk_-l.txt')
        kw1 = 'Disk /dev/'
        kw2 = 'mapper'
        main_template = (
            '<table class=\"new_table\">'
            '%s'
            '</table>'
        )
        sub_template = (
            '<tr>'
            '<td>%s</td>'
            '<td>%s</td>'
            '</tr>'
        )
        lns = self._format_file_content(fl)
        if lns:
            disk_tuples = [
                (
                    ln.split(':')[0].split()[1],
                    ln.split(':')[1].split(',')[0].strip()
                )
                for ln in lns
                if kw1 in ln and kw2 not in ln
            ]
            l = []
            for disk in disk_tuples:
                s = sub_template % disk
                l.append(s)
            disk_info = main_template % ''.join(l)
        else:
            disk_info = 'N/A'

        return {'disk_info': disk_info}


    def get_mem_info(self):
        fl = os.path.join(self.data_dir, 'meminfo.txt')
        lns = self._format_file_content(fl)
        if lns:
            mem_info = str(round(int(lns[0].split()[1])/1024, 2))
            mem_info = '%s MB' % mem_info

        return {'mem_info': mem_info}


    def get_lspci_info(self):
        fl = os.path.join(self.data_dir, 'lspci.txt')
        lns = self._format_file_content(fl)
        if lns:
            # fc_info
            kw = 'Fibre Channel'
            fc_info = list(set([
                ln.split(':')[2].strip()
                for ln in lns
                if kw in ln
            ])) or 'N/A'

            # raid_info
            kw = 'RAID'
            raid_info = [
                ln.split(':')[-1].strip()
                for ln in lns
                if kw in ln
            ] or 'N/A'

            # nic_info
            kw = 'Ethernet'
            template = '<table class=\"new_table\"><tr><td>%s</td></tr></table>'
            nic_all = [ln.split(':')[-1] for ln in lns if kw in ln]
            if len(nic_all) == 1:
                nic_info = template % nic_all[0]
            else:
                nic_info = template % '</td><td>'.join(nic_all) 
        else:
            fc_info = raid_info = nic_info = 'N/A'

        return {
            'fc_info': fc_info,
            'raid_info': raid_info,
            'nic_info': nic_info
        }


    def get_system_kernel(self):
        fl = os.path.join(self.data_dir, 'uname_-a.txt')
        lns = self._format_file_content(fl)
        system_kernel = lns[0].split()[2]

        return {'system_kernel': system_kernel}


    def get_system_install_time(self):
        fl = os.path.join(self.data_dir, 'rpm_-qi_ls.txt')
        kw = 'Install Date: '
        lns = self._format_file_content(fl)
        if lns:
            system_install_time = [
                ' '.join(ln.split(kw)[1].split()[:7])
                for ln in lns
                if kw in ln
            ][0]

            # get time zone
            time_set = system_install_time.split()[-1]
        else:
            system_install_time = time_set = 'N/A'

        return {
            'system_install_time': system_install_time,
            'time_set': time_set
        }


    def get_ulimit_set(self):
        fl = os.path.join(self.data_dir, 'limits.conf.txt')
        template = (
            '<table class=\"new_table\">'
            '<tr>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '<td>%s</td>'
            '</tr>'
            '</table>'
        )
        lns = self._format_file_content(fl)
        fl1 = os.path.join(self.data_dir, 'limits.d/90-nproc.conf')
        if os.path.isfile(fl1):
            extra = self._format_file_content(fl1)
            if extra:
                lns.extend(extra)
        ulimit_set_list = []
        for ln in lns:
            t = tuple(ln.split())
            if len(t) == 4:
                ulimit_set_list.append(template % t)
        ulimit_set = ''.join(ulimit_set_list) or '默认配置'

        return {'ulimit_set': ulimit_set}


    def get_ssh_info(self):
        # port
        fl = os.path.join(self.data_dir, 'sshd_config.txt')
        lns = self._format_file_content(fl)
        if lns:
            kw = 'Port'
            port = [ln for ln in lns if ln.startswith(kw)]
            openssh_port = port[0].split()[1] if port else '22'
        else:
            openssh_port = 'N/A'

        # sftp
        lns = self._format_file_content(fl)
        if lns:
            kw1 = 'Subsystem'
            kw2 = 'sftp'
            res = [ln for ln in lns if ln.startswith(kw1) and kw2 in ln]
            openssh_sftp_status = '已启用' if res else '未启用'
        else:
            openssh_sftp_status = 'N/A'

        # password auth
        lns = self._format_file_content(fl)
        if lns:
            kw1 = 'PasswordAuthentication'
            kw2 = 'yes'
            res = [ln for ln in lns if ln.startswith(kw1) and kw2 in ln]
            openssh_key_auth = '已启用' if res else '未启用'
            openssh_port = openssh_sftp_status = openssh_key_auth = 'N/A'
        else:
            openssh_port = 'N/A'

        return {
            'openssh_port': openssh_port,
            'openssh_sftp_status': openssh_sftp_status,
            'openssh_key_auth': openssh_key_auth
        }


    def get_task_info(self):
        fl = os.path.join(self.data_dir, 'crontab_-l.txt')
        main_template = '<table class=\"new_table\">%s</table>'
        lns = self._format_file_content(fl)
        if lns:
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
            lns = [tuple(ln.split()) for ln in lns]
            tasks = []
            for ln in lns:
                try:
                    s = sub_template % ln
                    tasks.append(s)
                except TypeError:
                    continue
            if tasks:
                task_info = main_template % ''.join(tasks)
            else:
                task_info = 'N/A'
        else:
            task_info = 'N/A'

        return {'task_info': task_info}


    def get_boot_mount_part(self):
        fl = os.path.join(self.data_dir, 'fstab.txt')
        lns = self._format_file_content(fl)
        main_template = '<table class=\"new_table\">%s</table>'
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
        lns = [tuple(ln.split()) for ln in lns]
        partitions = []
        for ln in lns:
            s = sub_template % ln
            partitions.append(s)
        boot_mount_part = main_template % ''.join(partitions)

        return {'boot_mount_part': boot_mount_part}


    def get_network_info(self):
        fl = os.path.join(self.data_dir, 'ip_addr.txt')
        lns = self._format_file_content(fl)

        # ethernet_info
        main_template = '<table class=\"new_table\">%s</table>'
        sub_template = '<tr><td>%s</td><td>%s</td></tr>'
        kws = ['inet ', 'bond', '127.0.0.']
        pairs = [
            (ln.split()[-1], ln.split()[1])
            for ln in lns
            if kws[0] in ln and not any(kw in ln for kw in kws[-2:])
        ]

        nics = []
        for pair in pairs:
            s = sub_template % pair
            nics.append(s)

        ethernet_info = main_template % ''.join(nics)

        # nic_bond_info
        main_template = (
            '<table class=\"new_table\">'
            '<tr>'
            '<th>name</th>'
            '<th>member</th>'
            '<th>status</th>'
            '</tr>'
            '%s'
            '</table>'
        )
        sub_template = '<tr><td>%s</td>%s<td>%s</td></tr>'
        kw1 = 'MASTER'
        masters = [ln.split(':')[1].strip() for ln in lns if kw1 in ln]

        if masters:
            pairs = []
            for master in masters:
                kw2 = 'master ' + master
                slaves = ', '.join([
                    ln.split(':')[1].strip()
                    for ln in lns
                    if kw2 in ln
                ])
                if slaves:
                    pairs.append((master, slaves, '启用'))
                else:
                    pairs.append((master, slaves, '未启用'))

            bonds = []
            for pair in pairs:
                s = sub_template % pair
                bonds.append(s)

            nic_bond_info = main_template % ''.join(bonds)
        else:
            nic_bond_info = 'N/A'

        return {'ethernet_info': ethernet_info, 'nic_bond_info': nic_bond_info}


    def get_multi_path_info(self):
        fl1 = os.path.join(self.data_dir, 'multipath_-ll.txt')
        fl2 = os.path.join(self.data_dir, 'powermt_display_dev.txt')
        kws = ['shaky', 'faulty', 'ghost', 'disabled', 'failed']
        msg = ['正常', '多路径异常，请检查']
        if os.path.isfile(fl1):
            try:
                multi_path_info = msg[1] if any(
                    kw in open(fl1).read() for kw in kws
                ) else msg[0]
            except UnicodeDecodeError:
                multi_path_info = msg[1] if any(
                    kw in open(fl1, encoding='gbk', errors='ignore').read() for kw in kws
                ) else msg[0]
        elif os.path.isfile(fl2):
            try:
                multi_path_info = msg[1] if any(
                    kw in open(fl2).read() for kw in kws
                ) else msg[0]
            except UnicodeDecodeError:
                multi_path_info = msg[1] if any(
                    kw in open(fl2, encoding='gbk', errors='ignore').read() for kw in kws
                ) else msg[0]
        else:
            multi_path_info = 'N/A'

        return {'multi_path_info': multi_path_info}


    def get_netstat(self):
        fl = os.path.join(self.data_dir, 'netstat_-antup.txt')
        lns = self._format_file_content(fl)

        # monitor_port
        main_template = (
            '<table class=\"new_table\">'
            '<tr>'
            '<th>Protocol</th>'
            '<th>Local Address</th>'
            '<th>State</th>'
            '<th>PID/Program name</th>'
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
            '</tr>'
        )
        pairs = [
            (
                ln.split()[0],
                ln.split()[3],
                ln.split()[5],
                ln.split()[-1]
            )
            for ln in lns[2:]
            if 'LISTEN' in ln
        ]
        uniq_pairs = set(pairs)
        l = []
        for pair in uniq_pairs:
            s = sub_template % pair
            l.append(s)
        monitor_port = main_template % ''.join(l)

        # net_established_nums
        kw1 = 'ESTABLISHED'
        net_established_nums = open(fl).read().count(kw1)
        
        # net_timewait_nums
        kw2 = 'TIME_WAIT'
        net_timewait_nums = open(fl).read().count(kw2)
        

        return {
            'monitor_port': monitor_port,
            'net_established_nums': net_established_nums,
            'net_timewait_nums': net_timewait_nums
        }


    def _chk_space(self, fl, main_template, sub_template, name):
        """This function is for the following chk_disk and chk_inode"""
        kws = ['sr0', '.iso', 'tmpfs']
        lns = self._format_file_content(fl)
        if lns:
            lns = [
                tuple(ln.split())
                for ln in lns
                if not any(kw in ln for kw in kws)
            ]
            disks = []
            for tp in lns[1:]:
                s = sub_template % tp
                disks.append(s)
            res = main_template % ''.join(disks)
        else:
            res = 'N/A'

        return {name: res} 

    def get_disk_space_usage(self):
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
            sub_template,
            'disk_space_usage'
        )

    def get_disk_inode_usage(self):
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
            sub_template,
            'disk_inode_usage'
        )


def run(tgz_dir):
    SysInfo.tgz_dir = tgz_dir
    iplist = [
        os.path.basename(tgz).split(SysInfo.suffix)[0]
        for tgz in glob.glob(SysInfo.tgz_dir + '/*' + SysInfo.suffix)
    ]
    exec_methods = [
        'get_check_time',
        'get_hostname',
        'get_os',
        'get_cpu_usage',
        'get_uptime',
        'get_mem',
        'get_shell_account',
        'get_product_name',
        'get_cpu_info',
        'get_disk_info',
        'get_mem_info',
        'get_lspci_info',
        'get_system_kernel',
        'get_system_install_time',
        'get_ulimit_set',
        'get_ssh_info',
        'get_task_info',
        'get_boot_mount_part',
        'get_network_info',
        'get_multi_path_info',
        'get_netstat',
        'get_disk_space_usage',
        'get_disk_inode_usage'
    ]

    data = {}
    for ip in iplist:
        sysinfo = SysInfo(ip)
        sysinfo._extract()
        data[ip] = {}
        for method in exec_methods:
            data[ip].update(getattr(sysinfo, method)())
    """
    Structure of data dict, data =
        {
            'ip1': {
                'item_name1': value,
                'item_name2': value,
                ...
            },
            'ip2': {
                'item_name1': value,
                'item_name2': value,
                ...
            },
            ...
        }
    """
    return data
