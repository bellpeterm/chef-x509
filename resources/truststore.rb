actions :create, :update, :delete

default_action :create

attribute :name, :kind_of => String, :name_attribute => true
attribute :path, :kind_of => String
attribute :user, :kind_of => String, :default => 'root'
attribute :group, :kind_of => String, :default => 'root'
attribute :mode, :kind_of => [Integer, String], :default => '0440'

attribute :certificates, :kind_of => Hash, :required => true
#attribute :resources, :kind_of => Array

attr_accessor :authorities
