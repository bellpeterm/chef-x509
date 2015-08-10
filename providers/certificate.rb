require 'digest/sha2'
require 'time'

use_inline_resources

action :create do

  file new_resource.certificate do
    owner new_resource.owner
    group new_resource.group
    mode "0644"
    action :nothing
  end
  file new_resource.key do
    owner new_resource.owner
    group new_resource.group
    mode "0600"
    action :nothing
  end
  if new_resource.cacertificate
    file new_resource.cacertificate do
      owner new_resource.owner
      group new_resource.group
      mode "0644"
      action :nothing
    end
  end

  # Load the current key, if it doesn't exist or the node is set to regenerate one
  key = load_key(node['x509']['regenerate_key'])
  certbag = get_signed_cert
  databag_cert = certbag ? EaSSL::Certificate.new({}).load(certbag[:certificate]) : false
  existing_cert = load_cert
  # If a cert can be obtained from the data_bag
  if databag_cert && x509_verify_key_cert_match(key, databag_cert)
    Chef::Log.debug('Found a matching cert in the data_bag')
    # Check if it's expiring; generate a csr if so, clear the csr if not
    if expiring?(databag_cert, node['x509']['expiry_threshold'])
      Chef::Log.debug('Certificate is expiring, creating a new CSR')
      generate_csr(key)
    else
      Chef::Log.debug('Certificate is OK, clearing csr_outbox')
      clear_csr
    end
    # Install the certificate
    Chef::Log.debug('Install certificate')
    install_certificate(certbag)
  # If a cert cannot be obtained from the data_bag, Check if there is a certificate installed
  elsif existing_cert && x509_verify_key_cert_match(key, existing_cert)
    Chef::Log.debug('Found a matching cert on the filesystem')
    # Check if the certificate is self-signed
    if existing_cert.ssl.issuer == existing_cert.ssl.subject
      Chef::Log.debug('Certificate is self-signed, ensuring a request is in csr_outbox')
      csr = generate_csr(key)
      # Check if the certificate is expired
      if expiring?(existing_cert, node['x509']['ss_expiry_threshold'])
        Chef::Log.debug('Certificate is expiring, creating a new self-signed cert')
        generate_ss_cert(csr, key)
      end

      if new_resource.provisionwait
        Chef::Log.debug("Waiting up to #{node['x509']['provision_wait_timeout']} seconds for certificate provisioning")
        certbag = wait_for_signed_cert(key)
        install_certificate(certbag) if certbag
      end
    else
      Chef::Log.debug('Certificate is not self-signed')
      if revoked?(existing_cert) && node['x509']['overwrite_revoked']
        Chef::Log.debug('Certificate is revoked and configured to overwrite')
        Chef::Log.debug('Generating new key/csr/self-signed cert')
        key = load_key(true)
        csr = generate_csr(key)
        generate_ss_cert(csr, key)
        if new_resource.provisionwait
          Chef::Log.debug("Waiting up to #{node['x509']['provision_wait_timeout']} seconds for certificate provisioning")
          certbag = wait_for_signed_cert(key)
          install_certificate(certbag) if certbag
        end
      end
      Chef::Log.debug('Certificate is valid but not in Chef')
      # Leave it alone, a signed cert exists but is not revoked now in the data_bag
      # It was deleted from the data_bag, created manually, or signed by an unrecognized CA
    end
  else
    Chef::Log.debug('No matching cert found, generating csr and self-signed cert')
    csr = generate_csr(key)
    generate_ss_cert(csr, key)
    if new_resource.provisionwait
      Chef::Log.debug("Waiting up to #{node['x509']['provision_wait_timeout']} seconds for certificate provisioning")
      certbag = wait_for_signed_cert(key)
      install_certificate(certbag) and clear_csr if certbag
    end
  end
end

def cert_id
  name_sha = Digest::SHA256.new << new_resource.name
  return name_sha.to_s
end

def install_certificate(certbag)
  Chef::Log.info("installing certificate #{new_resource.name} (id #{cert_id})")
  f = resource("file[#{new_resource.certificate}]")
  if new_resource.joincachain && certbag[:cacert]
    f.content certbag[:certificate] + certbag[:cacert]
  else
    f.content certbag[:certificate]
  end
  f.action :create

  if new_resource.cacertificate && certbag[:cacert]
    f = resource("file[#{new_resource.cacertificate}]")
    f.content certbag[:cacert]
    f.action :create
  end
end

def load_key(regenerate=false)
  key = nil
  if ::File.size?(new_resource.key) && ! regenerate
    key = x509_load_key(new_resource.key)
  else
    key = x509_generate_key(new_resource.bits)

    # write out the key
    f = resource("file[#{new_resource.key}]")
    f.content key.private_key.to_s
    f.action :create

    node.rm('x509', 'regenerate_key') if node['x509']['regenerate_key']
  end
  return key
end

def load_cert
  return ::File.size?(new_resource.certificate) ? x509_load_cert(new_resource.certificate) : false
end

def wait_for_signed_cert(key=nil)
  cert = nil
  timeout = Time.now + node['x509']['provision_wait_timeout']
  loop do
    cert = get_signed_cert
    break cert if cert and x509_verify_key_cert_match(key, EaSSL::Certificate.new({}).load(cert[:certificate]))
    return false if Time.now > timeout
    sleep node['x509']['provision_wait_interval']
  end
  cert
end

def get_signed_cert
  # Try to find this certificate in the data bag.
  certbag = search(:certificates, "id:#{cert_id}")
  certbag.sort_by! { |c| OpenSSL::X509::Certificate.new(c[:certificate]).not_after }
  return certbag.count > 0 ? certbag.last : false
end

def revoked?(certificate)
  certs = search(:revoked_certificates, "host:#{node.name}")
  revkd = certs.select do |c|
    revoked_cert = OpenSSL::X509::Certificate.new(c[:certificate])
    status = revoked_cert.subject == certificate.ssl.subject
    status = status and revoked_cert.issuer == certificate.ssl.issuer
    status = status and revoked_cert.serial == certificate.ssl.serial
    status = status and revoked_cert.not_after == certificate.ssl.not_after
    status
  end
  return revkd.count > 0
end

def expiring?(certificate, threshold=14)
  return certificate.ssl.not_after < Time.now + 24 * 60 * 60 * threshold
end

def generate_csr(key)
  # Generate the new CSR using provided key
  if node['csr_outbox'] and node['csr_outbox'][new_resource.name]
    csr = EaSSL::SigningRequest.new({}).load(node['csr_outbox'][new_resource.name][:csr])
    if csr.public_key.to_pem == key.public_key.to_pem and csr_fresh?
      return csr
    end
  end
  newcsr = x509_generate_csr({
    :key => key,
    :name => {
      :common_name => new_resource.cn || new_resource.name,
      :city => node['x509']['city'],
      :state => node['x509']['state'],
      :email => node['x509']['email'],
      :country => node['x509']['country'],
      :department => node['x509']['department'],
      :organization => node['x509']['organization']
    },
    :subject_alt_name => new_resource.subject_alt_name
  })

  node.set['csr_outbox'][new_resource.name] = {
    :id => cert_id,
    :csr => newcsr.to_pem,
    :key => node['x509']['key_vault'] ? gpg_encrypt(key.private_key.to_s, node['x509']['key_vault']) : nil,
    :ca => new_resource.ca,
    :date => Time.now.to_s,
    :type => new_resource.type,
    :days => new_resource.days
  }

  # Save node immediately so the CSR is published
  node.save
  Chef::Log.debug("Created new CSR")
  return newcsr
end

def clear_csr
  node.set['csr_outbox'][new_resource.name] = nil
end

def csr_fresh?
  Time.parse(node['csr_outbox'][new_resource.name][:date]) > Time.now - 60 * 60 * 24 * node['x509']['csr_freshness_threshold']
end

def generate_ss_cert(csr, key)
  cert = x509_issue_self_signed_cert(
    csr,
    key,
    new_resource.type
  )
  install_certificate({ :certificate => cert.to_pem })
end

def resource(name)
  return run_context.resource_collection.find(name)
end
