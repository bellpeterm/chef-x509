include X509::JavaStore

def load_current_resource
  @current_resource = Chef::Resource::X509Keystore.new(new_resource.name)
  pass = load_keystore_password(new_resource.path)
  @current_resource.identities = pass ? parse_keystore(storefile(new_resource.path), pass, :identity) : Array.new
end

action :create do

  pass = load_keystore_password(new_resource.path) || new_keystore_password(new_resource.path)
  kstor = storefile(new_resource.path || node['x509']['java_root'])

  missing_ids = new_resource.certificates - @current_resource.identities
  surplus_ids = @current_resource.identities - new_resource.certificates
  updatable_ids = @current_resource.identities - surplus_ids

  updated_certs = updatable_ids.map do |id|
    cert_res = find_certificate_resource(id)
  end.select do |cert_res|
    puts "Updatable Cert: " + cert_res.to_text + ' ' + cert_res.class.to_s + ' ' + cert_res.updated.to_s
    cert_res.class == Chef::Resource::X509Certificate ? cert_res.updated : false
  end

  puts "Updated Certs: " + updated_certs.to_s

  if missing_ids.count > 0 or surplus_ids.count > 0 or updated_certs.count > 0
    converge_by("Create certificates in #{ new_resource }: #{ missing_ids.join(', ') }") do

      surplus_ids.each do |id|
        Chef::Log.debug "Deleting extra id: " + id
        delete_entry(kstor, pass, id)
        new_resource.updated_by_last_action(true)
      end

      missing_ids.each do |id|
        Chef::Log.debug "Adding missing id: " + id
        cert_res = find_certificate_resource(id)
        add_identity(kstor, pass, cert_res)
        new_resource.updated_by_last_action(true)
      end

      updated_certs.each do |c|
        Chef::Log.debug "Deleting old cert: " + c.name
        delete_entry(kstor, pass, c.name)
        Chef::Log.debug "Adding updated cert: " + c.name
        add_identity(kstor, pass, c)
        new_resource.updated_by_last_action(true)
      end

      new_resource.updated_by_last_action(true)

      file kstor do
        user new_resource.user
        group new_resource.group
        mode new_resource.mode
        action :create
      end
    end
  end

end

action :delete do

  kstor = storefile(new_resource.path || node['x509']['java_root'])
  file kstor do
    action :delete
  end

end
