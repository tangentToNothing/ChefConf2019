#
# Cookbook:: hardening
# Recipe:: stigs
#
# Copyright:: 2019, The Authors, All Rights Reserved.

template '/etc/issue' do
    source 'issue.erb'
end

package 'screen'

template '/etc/pam.d/system-auth' do
    source 'system-auth.erb'
end

template '/etc/security/pwquality.conf' do
    source 'pwquality.conf.erb'
end

template '/etc/pam.d/password-auth' do
    source 'password-auth.erb'
end

template '/etc/login.defs' do
    source 'login.defs.erb'
end

template '/etc/ssh/sshd_config' do
    source 'sshd_config.erb'
end

template '/etc/yum.conf' do
    source 'yum.conf.erb'
end

template '/etc/cron.allow' do
    source 'cron.allow.erb'
end

template '/etc/pam.d/passwd' do
    source 'passwd.erb'
end

# run 'chage -m 1 [user]'