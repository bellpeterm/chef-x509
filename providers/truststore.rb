include X509::JavaStore

def load_current_resource
  @current_resource = Chef::Resource::X509Truststore.new(new_resource.name)
  pass = load_keystore_password(new_resource.path)
  @current_resource.authorities = pass ? parse_keystore(storefile(new_resource.path), pass, :authority) : Array.new
end

action :create do

  pass = load_keystore_password(new_resource.path) || new_keystore_password(new_resource.path)
  kstor = storefile(new_resource.path || node['x509']['java_root'])

  missing_ids = new_resource.certificates.keys - @current_resource.authorities
  surplus_ids = @current_resource.authorities - new_resource.certificates.keys
  updatable_ids = @current_resource.authorities - surplus_ids

  updated_certs = new_resource.certificates.select do |k,v|
    updatable_ids.include?(k) and run_context.resource_collection.find("file[#{v}]").updated
  end

  if missing_ids.count > 0 or surplus_ids.count > 0 or updated_certs.count > 0

    converge_by("Create authorities in #{ new_resource }: #{ missing_ids.join(', ') }") do

      surplus_ids.each do |v|
        Chef::Log.debug "Deleting extra authority: " + v
        delete_entry(kstor, pass, v)
        new_resource.updated_by_last_action(true)
      end

      missing_ids.each do |v|
        Chef::Log.debug "Adding missing authority: " + v
        add_authority(kstor, pass, v, new_resource.certificates[v])
        new_resource.updated_by_last_action(true)
      end

      updated_certs.each do |k,v|
        Chef::Log.debug "Deleting old authority: " + k
        delete_entry(kstor, pass, k)
        Chef::Log.debug "Adding updated authority: " + k
        add_authority(kstor, pass, k, v)
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
