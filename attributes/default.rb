# When set, the generated key will be GPG encrypted to this recipient,
# and the encrypted copy stored in node data. eg:
# default['x509']['key_vault'] = 'keyvault@example.com'
#
default['x509']['key_vault'] = nil

default['x509']['country'] = 'GB'
default['x509']['state'] = 'London'
default['x509']['city'] = 'London'
default['x509']['organization'] = 'Example Ltd'
default['x509']['department'] = 'Certificate Automation'
default['x509']['email'] = 'x509-auto@example.com'

case node['platform_family']
when 'rhel'
  default['x509']['tls_root'] = '/etc/pki/tls'
  default['x509']['java_root'] = '/etc/pki/java'
else
  default['x509']['tls_root'] = '/etc/ssl'
  default['x509']['java_root'] = '/etc/ssl'
end



# Ask for a new certificate if the current one will expire in __ days
default['x509']['expiry_threshold'] = 14
# Same but for self-signed certificates
default['x509']['ss_expiry_threshold'] = 1
# Number of days a CSR can remain unfulfilled before being re-created
default['x509']['csr_freshness_threshold'] = 14

# Have the Chef client wait for an issued certificate before continuing.
# Useful if a valid client certificate is needed later in the run_list.
# A service or job that regularly checks for csr requests is recommended.
default['x509']['provision_wait'] = false
default['x509']['provision_wait_timeout'] = 300
default['x509']['provision_wait_interval'] = 15

# Default should always be false, set true in normal attributes to force chef
# to regenerate keys. This should be done when revoking a certificate if the
# key is believed to be compromised.
default['x509']['regenerate_key'] = false

# If a certificate has been revoked but a new one is not available, set to true
# if the current (revoked) certificate should be overwritten with a new key and
# self-signed certificate
default['x509']['overwrite_revoked'] = false