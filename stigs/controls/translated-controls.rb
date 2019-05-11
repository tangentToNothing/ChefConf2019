# encoding: UTF-8

control "xccdf_mil.disa.stig_rule_SV-86487r3_rule" do
  title "The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon."
  desc  "
    Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
    
    System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
    
    The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:
    
    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
    
    By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    
    -At any time, the USG may inspect and seize data stored on this IS.
    
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"
    
    Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/issue") do
    its("content") { should match(/^(\\n|\s)*You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\)\s+that\s+is\s+provided\s+for\s+USG-authorized\s+use\s+only\.\s*(\\n|\n)+\s*By\s+using\s+this\s+IS\s+\(which\s+includes\s+any\s+device\s+attached\s+to\s+this\s+IS\),\s+you\s+consent\s+to\s+the\s+following\s+conditions\:\s*(\\n|\n)+\s*-The\s+USG\s+routinely\s+intercepts\s+and\s+monitors\s+communications\s+on\s+this\s+IS\s+for\s+purposes\s+including,\s+but\s+not\s+limited\s+to,\s+penetration\s+testing,\s+COMSEC\s+monitoring,\s+network\s+operations\s+and\s+defense,\s+personnel\s+misconduct\s+\(PM\),\s+law\s+enforcement\s+\(LE\),\s+and\s+counterintelligence\s+\(CI\)\s+investigations\.\s*(\\n|\n)+\s*-At\s+any\s+time,\s+the\s+USG\s+may\s+inspect\s+and\s+seize\s+data\s+stored\s+on\s+this\s+IS\.\s*(\\n|\n)+\s*-Communications\s+using,\s+or\s+data\s+stored\s+on,\s+this\s+IS\s+are\s+not\s+private,\s+are\s+subject\s+to\s+routine\s+monitoring,\s+interception,\s+and\s+search,\s+and\s+may\s+be\s+disclosed\s+or\s+used\s+for\s+any\s+USG-authorized\s+purpose\.\s*(\\n|\n)+\s*-This\s+IS\s+includes\s+security\s+measures\s+\(e\.g\.,\s+authentication\s+and\s+access\s+controls\)\s+to\s+protect\s+USG\s+interests--not\s+for\s+your\s+personal\s+benefit\s+or\s+privacy\.\s*(\\n|\n)+\s*-Notwithstanding\s+the\s+above,\s+using\s+this\s+IS\s+does\s+not\s+constitute\s+consent\s+to\s+PM,\s+LE\s+or\s+CI\s+investigative\s+searching\s+or\s+monitoring\s+of\s+the\s+content\s+of\s+privileged\s+communications,\s+or\s+work\s+product,\s+related\s+to\s+personal\s+representation\s+or\s+services\s+by\s+attorneys,\s+psychotherapists,\s+or\s+clergy,\s+and\s+their\s+assistants\.\s+Such\s+communications\s+and\s+work\s+product\s+are\s+private\s+and\s+confidential\.\s+See\s+User\s+Agreement\s+for\s+details\.(\\n|\s)*$/)}
  end
  
  permitted_lines = [/^(\\n|\s)*You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\)\s+that\s+is\s+provided\s+for\s+USG-authorized\s+use\s+only\.\s*(\\n|\n)+\s*By\s+using\s+this\s+IS\s+\(which\s+includes\s+any\s+device\s+attached\s+to\s+this\s+IS\),\s+you\s+consent\s+to\s+the\s+following\s+conditions\:\s*(\\n|\n)+\s*-The\s+USG\s+routinely\s+intercepts\s+and\s+monitors\s+communications\s+on\s+this\s+IS\s+for\s+purposes\s+including,\s+but\s+not\s+limited\s+to,\s+penetration\s+testing,\s+COMSEC\s+monitoring,\s+network\s+operations\s+and\s+defense,\s+personnel\s+misconduct\s+\(PM\),\s+law\s+enforcement\s+\(LE\),\s+and\s+counterintelligence\s+\(CI\)\s+investigations\.\s*(\\n|\n)+\s*-At\s+any\s+time,\s+the\s+USG\s+may\s+inspect\s+and\s+seize\s+data\s+stored\s+on\s+this\s+IS\.\s*(\\n|\n)+\s*-Communications\s+using,\s+or\s+data\s+stored\s+on,\s+this\s+IS\s+are\s+not\s+private,\s+are\s+subject\s+to\s+routine\s+monitoring,\s+interception,\s+and\s+search,\s+and\s+may\s+be\s+disclosed\s+or\s+used\s+for\s+any\s+USG-authorized\s+purpose\.\s*(\\n|\n)+\s*-This\s+IS\s+includes\s+security\s+measures\s+\(e\.g\.,\s+authentication\s+and\s+access\s+controls\)\s+to\s+protect\s+USG\s+interests--not\s+for\s+your\s+personal\s+benefit\s+or\s+privacy\.\s*(\\n|\n)+\s*-Notwithstanding\s+the\s+above,\s+using\s+this\s+IS\s+does\s+not\s+constitute\s+consent\s+to\s+PM,\s+LE\s+or\s+CI\s+investigative\s+searching\s+or\s+monitoring\s+of\s+the\s+content\s+of\s+privileged\s+communications,\s+or\s+work\s+product,\s+related\s+to\s+personal\s+representation\s+or\s+services\s+by\s+attorneys,\s+psychotherapists,\s+or\s+clergy,\s+and\s+their\s+assistants\.\s+Such\s+communications\s+and\s+work\s+product\s+are\s+private\s+and\s+confidential\.\s+See\s+User\s+Agreement\s+for\s+details\.(\\n|\s)*$/,
  
  /^\s+$/,
  
  /^\s*You\s+are\s+accessing\s+a\s+U\.S\.\s+Government\s+\(USG\)\s+Information\s+System\s+\(IS\)\s+that\s+is\s+provided\s+for\s+USG-authorized\s+use\s+only\.\s*$",
  "^\s*By\s+using\s+this\s+IS\s+\(which\s+includes\s+any\s+device\s+attached\s+to\s+this\s+IS\),\s+you\s+consent\s+to\s+the\s+following\s+conditions\:\s*$/,
  
  /^\s*-The\s+USG\s+routinely\s+intercepts\s+and\s+monitors\s+communications\s+on\s+this\s+IS\s+for\s+purposes\s+including,\s+but\s+not\s+limited\s+to,\s+penetration\s+testing,\s+COMSEC\s+monitoring,\s+network\s+operations\s+and\s+defense,\s+personnel\s+misconduct\s+\(PM\),\s+law\s+enforcement\s+\(LE\),\s+and\s+counterintelligence\s+\(CI\)\s+investigations\.\s*$/,
  
  /^\s*-At\s+any\s+time,\s+the\s+USG\s+may\s+inspect\s+and\s+seize\s+data\s+stored\s+on\s+this\s+IS\.\s*$/,
  
  /^\s*-Communications\s+using,\s+or\s+data\s+stored\s+on,\s+this\s+IS\s+are\s+not\s+private,\s+are\s+subject\s+to\s+routine\s+monitoring,\s+interception,\s+and\s+search,\s+and\s+may\s+be\s+disclosed\s+or\s+used\s+for\s+any\s+USG-authorized\s+purpose\.\s*$/,
  
  /^\s*-This\s+IS\s+includes\s+security\s+measures\s+\(e\.g\.,\s+authentication\s+and\s+access\s+controls\)\s+to\s+protect\s+USG\s+interests--not\s+for\s+your\s+personal\s+benefit\s+or\s+privacy\.\s*$/,
  
  /^\s*-Notwithstanding\s+the\s+above,\s+using\s+this\s+IS\s+does\s+not\s+constitute\s+consent\s+to\s+PM,\s+LE\s+or\s+CI\s+investigative\s+searching\s+or\s+monitoring\s+of\s+the\s+content\s+of\s+privileged\s+communications,\s+or\s+work\s+product,\s+related\s+to\s+personal\s+representation\s+or\s+services\s+by\s+attorneys,\s+psychotherapists,\s+or\s+clergy,\s+and\s+their\s+assistants\.\s+Such\s+communications\s+and\s+work\s+product\s+are\s+private\s+and\s+confidential\.\s+See\s+User\s+Agreement\s+for\s+details\.\s*$/]
  
  unpermitted_lines = file("/etc/issue").content.split("\n").delete_if { |l| permitted_lines.find { |x| l =~ x } }
  describe unpermitted_lines do
    it { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-86521r2_rule" do
  title "The Red Hat Enterprise Linux operating system must have the screen package installed."
  desc  "
    Vulnerability Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
    
    The screen package allows for a session lock to be implemented and configured.
    
    Documentable: false
    
  "
  impact 0.5
  describe package("screen") do
    it { should be_installed }
  end
end


control "xccdf_mil.disa.stig_rule_SV-86527r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one upper-case character."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^ucredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^ucredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= -1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86529r5_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one lower-case character."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^lcredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^lcredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= -1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86531r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are assigned, the new password must contain at least one numeric character."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^dcredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^dcredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= -1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86533r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one special character."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^ocredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^ocredit[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= -1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86535r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of eight of the total number of characters must be changed."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^difok[\s]*=[\s]*(\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^difok[\s]*=[\s]*(\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 8 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86537r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed a minimum of four character classes must be changed."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^minclass[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^minclass[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 4 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86539r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed the number of repeating consecutive characters must not be more than three characters."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^maxrepeat[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^maxrepeat[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 3 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86541r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed the number of repeating characters of the same character class must not be more than four characters."
  desc  "
    Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
    
    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:(?:required)|(?:requisite))\s+pam_pwquality\.so.*$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^maxclassrepeat[\s]*=[\s]*(-?\d+)(?:[\s]|$)/) }
  end
  file("/etc/security/pwquality.conf").content.to_s.scan(/^maxclassrepeat[\s]*=[\s]*(-?\d+)(?:[\s]|$)/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 4 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86543r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the PAM system service is configured to store only encrypted representations of passwords."
  desc  "
    Vulnerability Discussion: Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/) }
  end
  describe file("/etc/pam.d/system-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten do
    its("length") { should >= 1 }
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]))sha512(?:\s|$)/) }
    end
  end
  file("/etc/pam.d/system-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten.each do |entry|
    describe entry do
      it { should_not match(/^(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]))(?:md5|sha256|bigcrypt|blowfish)(?:\s|$)/) }
    end
  end
  describe file("/etc/pam.d/password-auth") do
    its("content") { should match(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/) }
  end
  describe file("/etc/pam.d/password-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten do
    its("length") { should >= 1 }
  end
  file("/etc/pam.d/password-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]))sha512(?:\s|$)/) }
    end
  end
  file("/etc/pam.d/password-auth").content.to_s.scan(/^[\s]*password[ \t]+(?:(?:required)|(?:sufficient))[ \t]+pam_unix\.so(.*)$/).flatten.each do |entry|
    describe entry do
      it { should_not match(/^(?:[ \t]+|(?:[ \t][^#\r\f\n]+[ \t]))(?:md5|sha256|bigcrypt|blowfish)(?:\s|$)/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86549r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 24 hours/1 day minimum lifetime."
  desc  "
    Vulnerability Discussion: Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MIN_DAYS\s+(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*PASS_MIN_DAYS\s+(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 1 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86553r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that passwords for new users are restricted to a 60-day maximum lifetime."
  desc  "
    Vulnerability Discussion: Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MAX_DAYS\s+(\d+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*PASS_MAX_DAYS\s+(\d+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 60 }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86581r3_rule" do
  title "The Red Hat Enterprise Linux operating system must not allow users to override SSH environment variables."
  desc  "
    Vulnerability Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("PermitUserEnvironment") { should_not be_nil }
    its("PermitUserEnvironment") { should cmp "no" }
  end
end

control "xccdf_mil.disa.stig_rule_SV-86583r3_rule" do
  title "The Red Hat Enterprise Linux operating system must not allow a non-certificate trusted host SSH logon to the system."
  desc  "
    Vulnerability Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  describe sshd_config("/etc/ssh/sshd_config") do
    its("HostbasedAuthentication") { should_not be_nil }
    its("HostbasedAuthentication") { should cmp "no" }
  end
end

control "xccdf_mil.disa.stig_rule_SV-86611r2_rule" do
  title "The Red Hat Enterprise Linux operating system must remove all software components after updated versions have been installed."
  desc  "
    Vulnerability Discussion: Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.
    
    Documentable: false
    
  "
  impact 0.1
  describe file("/etc/yum.conf") do
    its("content") { should match(/^\s*clean_requirements_on_remove\s*=\s*(\S+)\s*$/) }
  end
  file("/etc/yum.conf").content.to_s.scan(/^\s*clean_requirements_on_remove\s*=\s*(\S+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should match(/^(1|True|yes)$/) }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86619r2_rule" do
  title "The Red Hat Enterprise Linux operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
  desc  "
    Vulnerability Discussion: Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.
    
    Documentable: false
    
  "
  impact 0.5
  describe command('grep \'^[\s]*UMASK.\+[0-9]*\' /etc/login.defs') do
    its('exit_status') { should eq 0 }
  end
  describe command('grep \'^[\s]*UMASK.\+[0-9]*\' /etc/login.defs').stdout.split.reject { |f| f == 'UMASK' }.first do
    it { should eq '077' }
  end
end


control "xccdf_mil.disa.stig_rule_SV-86637r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that all local interactive user accounts, upon creation, are assigned a home directory."
  desc  "
    Vulnerability Discussion: If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*CREATE_HOME\s+(\S+)\s*$/) }
  end
  file("/etc/login.defs").content.to_s.scan(/^\s*CREATE_HOME\s+(\S+)\s*$/).flatten.each do |entry|
    describe entry do
      it { should eq "yes" }
    end
  end
end

control "xccdf_mil.disa.stig_rule_SV-86671r4_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that all world-writable directories are group-owned by root, sys, bin, or an application group."
  desc  "
    Vulnerability Discussion: If a world-writable directory has the sticky bit set and is not group-owned by a privileged Group Identifier (GID), unauthorized users may be able to modify files created by others.
    
    The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.
    
    Documentable: false
    
  "
  impact 0.5
  describe command("find / -type d -perm -00002 -user 1000 -user +1000 -xdev") do
    its("stdout") { should be_empty }
  end
end

control "xccdf_mil.disa.stig_rule_SV-86677r3_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is owned by root."
  desc  "
    Vulnerability Discussion: If the owner of the \"cron.allow\" file is not set to root, the possibility exists for an unauthorized user to view or to edit sensitive information.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    its("uid") { should cmp 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-86679r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the cron.allow file, if it exists, is group-owned by root."
  desc  "
    Vulnerability Discussion: If the group owner of the \"cron.allow\" file is not set to root, sensitive information could be viewed or edited by unauthorized users.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    its("gid") { should cmp 0 }
  end
end

control "xccdf_mil.disa.stig_rule_SV-95715r1_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords."
  desc  "
    Vulnerability Discussion: Pluggable authentication modules (PAM) allow for a modular approach to integrating authentication methods. PAM operates in a top-down processing model and if the modules are not listed in the correct order, an important security function could be bypassed if stack entries are not centralized.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/etc/pam.d/passwd") do
    its("content") { should match(/^[\s]*password[ \t]+substack[ \t]+system-auth\s*$/) }
  end
end