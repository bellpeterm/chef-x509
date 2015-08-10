module X509
  module JavaStore
    require 'securerandom'
    require 'mkmf'
    require 'mixlib/shellout'

    def load_keystore_password(path)
      pfile = passfile(path)
      pass = ::File.open(pfile, 'r') { |f| f.read } if ::File.exists?(pfile)
      return (defined?(pass) and pass.class == String and ! pass.empty?) ? pass : nil
    end

    def new_keystore_password(path)
      pass = SecureRandom.urlsafe_base64(32)
      pfile = passfile(path)

      file pfile do
        content pass
        user new_resource.user
        group new_resource.group
        mode new_resource.mode
        action :create_if_missing
      end

      return pass
    end

    def storefile(path)
      path ||= node['x509']['java_root']
      ::File.join(path, new_resource.name + '.keystore')
    end

    def passfile(path)
      path ||= node['x509']['java_root']
      ::File.join(path, new_resource.name + '.keystore_pass')
    end

    def find_certificate_resource(certname)
      run_context.resource_collection.find("x509_certificate[#{certname}]")
    end

    def find_cacertificate_resource(cacertname)
      run_context.resource_collection.find("x509_cacertificate[#{cacertname}]")
    end

    def parse_keystore(store, pass, type=:all)
      command = Array.new
      command << 'keytool -list -keystore'
      command << store
      command << '-storepass'
      command << pass
      ktcmd = Mixlib::ShellOut.new(command.join(' '), :cwd => ::File.dirname(store))
      ktcmd.run_command

      ids = ktcmd.stdout.split(/\n/).select do |s|
        case type
        when :identity
          s.match(/PrivateKeyEntry/)
        when :authority
          s.match(/trustedCertEntry/)
        else
          s.match(/PrivateKeyEntry|trustedCertEntry/)
        end
      end.map do |s|
        s.split(',').first
      end

      return ids
    end

    def create_temp_p12store(store, pass, certificate_resource)
      p12store = store + SecureRandom.hex(4) + '.p12'

      file p12store do
        action :nothing
        subscribes :delete, new_resource, :delayed
      end

      command = Array.new
      command << 'openssl pkcs12 -export -in'
      command << certificate_resource.certificate
      command << '-inkey'
      command << certificate_resource.key
      command << '-out'
      command << p12store
      command << '-name'
      command << certificate_resource.name
      if certificate_resource.cacertificate and ::File.exists?(certificate_resource.cacertificate)
        command << '-chain -CAfile'
        command << certificate_resource.cacertificate
      end
      command << '-password stdin'

      osslcmd = Mixlib::ShellOut.new(command.join(' '), :cwd => ::File.dirname(store), :input => pass)
      osslcmd.run_command

      return p12store
    end

    def add_identity(store, pass, certificate_resource)
      idfile = create_temp_p12store(store, pass, certificate_resource)

      command = Array.new
      command << 'keytool -importkeystore -noprompt'
      command << '-srcstoretype PKCS12 -srckeystore'
      command << idfile
      command << '-deststoretype JKS -destkeystore'
      command << store
      command << '-srcstorepass'
      command << pass
      command << '-deststorepass'
      command << pass
      command << '-alias'
      command << certificate_resource.name

      ktcmd = Mixlib::ShellOut.new(command.join(' '), :cwd => ::File.dirname(store))
      ktcmd.run_command
    end

    def add_authority(store, pass, name, path)
      command = Array.new
      command << 'keytool -importcert -noprompt -trustcacerts'
      command << '-file'
      command << name
      command << '-keystore'
      command << store
      command << '-storepass'
      command << pass
      command << '-alias'
      command << name
      command << '-file'
      command << path

      Chef::Log.debug("Running: #{command.join(' ')}")

      ktcmd = Mixlib::ShellOut.new(command.join(' '), :cwd => ::File.dirname(store))
      ktcmd.run_command
    end

    def delete_entry(store, pass, entry)
      command = Array.new
      command << 'keytool -delete -alias'
      command << entry
      command << '-keystore'
      command << store
      command << '-storepass'
      command << pass

      ktcmd = Mixlib::ShellOut.new(command.join(' '), :cwd => ::File.dirname(store))
      ktcmd.run_command
    end

  end
end
