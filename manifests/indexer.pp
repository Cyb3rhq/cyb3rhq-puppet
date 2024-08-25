# Copyright (C) 2015, Cyb3rhq Inc.
# Setup for Cyb3rhq Indexer
class cyb3rhq::indexer (
  # opensearch.yml configuration
  $indexer_network_host = '0.0.0.0',
  $indexer_cluster_name = 'cyb3rhq-cluster',
  $indexer_node_name = 'node-1',
  $indexer_node_max_local_storage_nodes = '1',
  $indexer_service = 'cyb3rhq-indexer',
  $indexer_package = 'cyb3rhq-indexer',
  $indexer_version = '5.0.0-1',
  $indexer_fileuser = 'cyb3rhq-indexer',
  $indexer_filegroup = 'cyb3rhq-indexer',

  $indexer_path_data = '/var/lib/cyb3rhq-indexer',
  $indexer_path_logs = '/var/log/cyb3rhq-indexer',
  $indexer_path_certs = '/etc/cyb3rhq-indexer/certs',
  $indexer_security_init_lockfile = '/var/tmp/indexer-security-init.lock',
  $full_indexer_reinstall = false, # Change to true when whant a full reinstall of Cyb3rhq indexer

  $indexer_ip = 'localhost',
  $indexer_port = '9200',
  $indexer_discovery_hosts = [], # Empty array for single-node configuration
  $indexer_cluster_initial_master_nodes = ['node-1'],
  $indexer_cluster_CN = ['node-1'],

  # JVM options
  $jvm_options_memory = '1g',
) {

  # install package
  package { 'cyb3rhq-indexer':
    ensure => $indexer_version,
    name   => $indexer_package,
  }

  exec { "ensure full path of ${indexer_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${indexer_path_certs}",
    creates => $indexer_path_certs,
    require => Package['cyb3rhq-indexer'],
  }
  -> file { $indexer_path_certs:
    ensure => directory,
    owner  => $indexer_fileuser,
    group  => $indexer_filegroup,
    mode   => '0500',
  }

  [
   "indexer-$indexer_node_name.pem",
   "indexer-$indexer_node_name-key.pem",
   'root-ca.pem',
   'admin.pem',
   'admin-key.pem',
  ].each |String $certfile| {
    file { "${indexer_path_certs}/${certfile}":
      ensure  => file,
      owner   => $indexer_fileuser,
      group   => $indexer_filegroup,
      mode    => '0400',
      replace => true,
      recurse => remote,
      source  => "puppet:///modules/archive/${certfile}",
    }
  }



  file { 'configuration file':
    path    => '/etc/cyb3rhq-indexer/opensearch.yml',
    content => template('cyb3rhq/cyb3rhq_indexer_yml.erb'),
    group   => $indexer_filegroup,
    mode    => '0660',
    owner   => $indexer_fileuser,
    require => Package['cyb3rhq-indexer'],
    notify  => Service['cyb3rhq-indexer'],
  }

  file_line { 'Insert line initial size of total heap space':
    path    => '/etc/cyb3rhq-indexer/jvm.options',
    line    => "-Xms${jvm_options_memory}",
    match   => '^-Xms',
    require => Package['cyb3rhq-indexer'],
    notify  => Service['cyb3rhq-indexer'],
  }

  file_line { 'Insert line maximum size of total heap space':
    path    => '/etc/cyb3rhq-indexer/jvm.options',
    line    => "-Xmx${jvm_options_memory}",
    match   => '^-Xmx',
    require => Package['cyb3rhq-indexer'],
    notify  => Service['cyb3rhq-indexer'],
  }

  service { 'cyb3rhq-indexer':
    ensure  => running,
    enable  => true,
    name    => $indexer_service,
    require => Package['cyb3rhq-indexer'],
  }

  file_line { "Insert line limits nofile for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - nofile  65535",
    match  => "^${indexer_fileuser} - nofile\s",
    notify => Service['cyb3rhq-indexer'],
  }
  file_line { "Insert line limits memlock for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - memlock unlimited",
    match  => "^${indexer_fileuser} - memlock\s",
    notify => Service['cyb3rhq-indexer'],
  }

  # TODO: this should be done by the package itself and not by puppet at all
  [
    '/etc/cyb3rhq-indexer',
    '/usr/share/cyb3rhq-indexer',
    '/var/lib/cyb3rhq-indexer',
  ].each |String $file| {
    exec { "set recusive ownership of ${file}":
      path        => '/usr/bin:/bin',
      command     => "chown ${indexer_fileuser}:${indexer_filegroup} -R ${file}",
      refreshonly => true,  # only run when package is installed or updated
      subscribe   => Package['cyb3rhq-indexer'],
      notify      => Service['cyb3rhq-indexer'],
    }
  }

  if $full_indexer_reinstall {
    file { $indexer_security_init_lockfile:
      ensure  => absent,
      require => Package['cyb3rhq-indexer'],
      before  => Exec['Initialize the Opensearch security index in Cyb3rhq indexer'],
    }
  }
}
