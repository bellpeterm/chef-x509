include_recipe 'x509_test::san_cert'

x509_keystore 'www.example.com' do
  certificates ['service-www.example.com']
end
