include_recipe 'x509_test::san_cert'

x509_truststore 'www.example.com-truststore' do
  certificates({
    'cshtc' => ::File.join(node['x509']['tls_root'], 'certs', 'cshtc.crt')
  })
end
