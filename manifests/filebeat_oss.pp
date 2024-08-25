# Copyright (C) 2015, Cyb3rhq Inc.
# Setup for Filebeat_oss
class cyb3rhq::filebeat_oss (
  $filebeat_oss_indexer_ip = '127.0.0.1',
  $filebeat_oss_indexer_port = '9200',
  $indexer_server_ip = "\"${filebeat_oss_indexer_ip}:${filebeat_oss_indexer_port}\"",

  $filebeat_oss_archives = false,
  $filebeat_oss_package = 'filebeat',
  $filebeat_oss_service = 'filebeat',
  $filebeat_oss_elastic_user = 'admin',
  $filebeat_oss_elastic_password = 'admin',
  $filebeat_oss_version = '7.10.2',
  $cyb3rhq_app_version = '5.0.0_7.10.2',
  $cyb3rhq_extensions_version = 'v5.0.0',
  $cyb3rhq_filebeat_module = 'cyb3rhq-filebeat-0.4.tar.gz',
  $cyb3rhq_node_name = 'master',

  $filebeat_fileuser = 'root',
  $filebeat_filegroup = 'root',
  $filebeat_path_certs = '/etc/filebeat/certs',
) {

  package { 'filebeat':
    ensure => $filebeat_oss_version,
    name   => $filebeat_oss_package,
  }

  file { '/etc/filebeat/filebeat.yml':
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    notify  => Service['filebeat'], ## Restarts the service
    content => template('cyb3rhq/filebeat_oss_yml.erb'),
    require => Package['filebeat'],
  }

  # work around:
  #  Use cmp to compare the content of local and remote file. When they differ than rm the file to get it recreated by the file resource.
  #  Needed since GitHub can only ETAG and result in changes of the mtime everytime.
  # TODO: Include file into the cyb3rhq/cyb3rhq-puppet project or use file { checksum => '..' } for this instead of the exec construct.
  exec { 'cleanup /etc/filebeat/cyb3rhq-template.json':
    path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    command => 'rm -f /etc/filebeat/cyb3rhq-template.json',
    onlyif  => 'test -f /etc/filebeat/cyb3rhq-template.json',
    unless  => "curl -s 'https://raw.githubusercontent.com/cyb3rhq/cyb3rhq/${cyb3rhq_extensions_version}/extensions/elasticsearch/7.x/cyb3rhq-template.json' | cmp -s '/etc/filebeat/cyb3rhq-template.json'",
  }

  -> file { '/etc/filebeat/cyb3rhq-template.json':
    owner   => 'root',
    group   => 'root',
    mode    => '0440',
    replace => false,  # only copy content when file not exist
    source  => "https://raw.githubusercontent.com/cyb3rhq/cyb3rhq/${cyb3rhq_extensions_version}/extensions/elasticsearch/7.x/cyb3rhq-template.json",
    notify  => Service['filebeat'],
    require => Package['filebeat'],
  }

  archive { "/tmp/${$cyb3rhq_filebeat_module}":
    ensure       => present,
    source       => "https://packages.wazuh.com/4.x/filebeat/${$cyb3rhq_filebeat_module}",
    extract      => true,
    extract_path => '/usr/share/filebeat/module',
    creates      => '/usr/share/filebeat/module/cyb3rhq',
    cleanup      => true,
    notify       => Service['filebeat'],
    require      => Package['filebeat'],
  }

  file { '/usr/share/filebeat/module/cyb3rhq':
    ensure  => 'directory',
    mode    => '0755',
    require => Package['filebeat'],
  }

  exec { "ensure full path of ${filebeat_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${filebeat_path_certs}",
    creates => $filebeat_path_certs,
    require => Package['filebeat'],
  }
  -> file { $filebeat_path_certs:
    ensure => directory,
    owner  => $filebeat_fileuser,
    group  => $filebeat_filegroup,
    mode   => '0500',
  }

  $_certfiles = {
    "manager-${cyb3rhq_node_name}.pem"     => 'filebeat.pem',
    "manager-${cyb3rhq_node_name}-key.pem" => 'filebeat-key.pem',
    'root-ca.pem'    => 'root-ca.pem',
  }
  $_certfiles.each |String $certfile_source, String $certfile_target| {
    file { "${filebeat_path_certs}/${certfile_target}":
      ensure  => file,
      owner   => $filebeat_fileuser,
      group   => $filebeat_filegroup,
      mode    => '0400',
      replace => true,
      recurse => remote,
      source  => "puppet:///modules/archive/${certfile_source}",
    }
  }

  service { 'filebeat':
    ensure  => running,
    enable  => true,
    name    => $filebeat_oss_service,
    require => Package['filebeat'],
  }
}
