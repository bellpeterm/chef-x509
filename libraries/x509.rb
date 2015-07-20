begin
  require 'eassl'
rescue LoadError => e
  Chef::Log.warn("X509 library dependency 'eassl' not loaded: #{e}")
end

def x509_generate_key(bits)
  return EaSSL::Key.new(:bits => bits)
end

def x509_load_key(path)
  return EaSSL::Key.load(path)
end

def x509_load_cert(path)
  return EaSSL::Certificate.load(path)
end

def x509_generate_csr(info)
  ea_name = EaSSL::CertificateName.new(info[:name])
  ea_csr  = EaSSL::SigningRequest.new(info.merge({:name => ea_name}))
  ea_csr
end

def x509_issue_self_signed_cert(csr, key, type)
  # Self-signed certificate where subject == issuer with own key
  cert = EaSSL::Certificate.new(
    :type => type,
    :signing_request => csr
  )
  cert.sign(key)
  return cert
end

def x509_verify_key_cert_match(key, cert)
  return false if key.class != EaSSL::Key or cert.class != EaSSL::Certificate
  key.n == cert.public_key.n
end

def urlsafe_encode64(bin)
  if Base64.respond_to?(:urlsafe_encode64)
    # Only available in Ruby 1.9
    Base64.urlsafe_encode64(bin)
  else
    [bin].pack("m0").chomp("\n").tr("+/", "-_")
  end
end

#return an array of revoked certificate serial numbers
def x509_revoked_serials()
  serials = Array.new()
  certs = search(:revoked_certificates)
  certs.each do |cert|
    serials << cert['serial']
  end
  return serials
end

#private get a crl item for the CA specified from the data bag
def x509_get_crl(caname)
  # search for CRL in one of its issued certificate databags
  items = search('certificate_revocation_list', "ca:#{caname}") 
  if items.nil? or items.size == 0
    raise "Could not find CRL for CA '#{caname}'"
  elsif items.size > 1
    raise "Found more than one CRL for CA '#{caname}', there can only be one."
  end
  return items[0]
end

#for a caname in the certificate_revocation_list data bag, return the path to the file
def x509_get_crl_path(caname) 
  item = x509_get_crl(caname)
  return ::File.join(node['x509']['tls_root'], 'certs', "#{item['hash']}}.r0")
end
