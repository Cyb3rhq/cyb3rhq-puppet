# Copyright (C) 2015, Cyb3rhq Inc.
# Setup for Cyb3rhq Dashboard
class cyb3rhq::dashboard (
  $dashboard_package = 'cyb3rhq-dashboard',
  $dashboard_service = 'cyb3rhq-dashboard',
  $dashboard_version = '5.0.0',
  $indexer_server_ip = 'localhost',
  $indexer_server_port = '9200',
  $manager_api_host = '127.0.0.1',
  $dashboard_path_certs = '/etc/cyb3rhq-dashboard/certs',
  $dashboard_fileuser = 'cyb3rhq-dashboard',
  $dashboard_filegroup = 'cyb3rhq-dashboard',

  $dashboard_server_port = '443',
  $dashboard_server_host = '0.0.0.0',
  $dashboard_server_hosts = "https://${indexer_server_ip}:${indexer_server_port}",

  # If the keystore is used, the credentials are not managed by the module (TODO).
  # If use_keystore is false, the keystore is deleted, the dashboard use the credentials in the configuration file.
  $use_keystore = true,
  $dashboard_user = 'kibanaserver',
  $dashboard_password = 'kibanaserver',

  $dashboard_cyb3rhq_api_credentials = [
    {
      'id'       => 'default',
      'url'      => "https://${manager_api_host}",
      'port'     => '55000',
      'user'     => 'cyb3rhq-wui',
      'password' => 'cyb3rhq-wui',
    },
  ],

) {

  # assign version according to the package manager
  case $facts['os']['family'] {
    'Debian': {
      $dashboard_version_install = "${dashboard_version}-*"
    }
    'Linux', 'RedHat', default: {
      $dashboard_version_install = $dashboard_version
    }
  }

  # install package
  package { 'cyb3rhq-dashboard':
    ensure => $dashboard_version_install,
    name   => $dashboard_package,
  }

  exec { "ensure full path of ${dashboard_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${dashboard_path_certs}",
    creates => $dashboard_path_certs,
    require => Package['cyb3rhq-dashboard'],
  }
  -> file { $dashboard_path_certs:
    ensure => directory,
    owner  => $dashboard_fileuser,
    group  => $dashboard_filegroup,
    mode   => '0500',
  }

  [
    'dashboard.pem',
    'dashboard-key.pem',
    'root-ca.pem',
  ].each |String $certfile| {
    file { "${dashboard_path_certs}/${certfile}":
      ensure  => file,
      owner   => $dashboard_fileuser,
      group   => $dashboard_filegroup,
      mode    => '0400',
      replace => true,
      recurse => remote,
      source  => "puppet:///modules/archive/${certfile}",
    }
  }

  file { '/etc/cyb3rhq-dashboard/opensearch_dashboards.yml':
    content => template('cyb3rhq/cyb3rhq_dashboard_yml.erb'),
    group   => $dashboard_filegroup,
    mode    => '0640',
    owner   => $dashboard_fileuser,
    require => Package['cyb3rhq-dashboard'],
    notify  => Service['cyb3rhq-dashboard'],
  }

  file { [ '/usr/share/cyb3rhq-dashboard/data/cyb3rhq/', '/usr/share/cyb3rhq-dashboard/data/cyb3rhq/config' ]:
    ensure  => 'directory',
    group   => $dashboard_filegroup,
    mode    => '0755',
    owner   => $dashboard_fileuser,
    require => Package['cyb3rhq-dashboard'],
  }
  -> file { '/usr/share/cyb3rhq-dashboard/data/cyb3rhq/config/cyb3rhq.yml':
    content => template('cyb3rhq/cyb3rhq_yml.erb'),
    group   => $dashboard_filegroup,
    mode    => '0600',
    owner   => $dashboard_fileuser,
    notify  => Service['cyb3rhq-dashboard'],
  }

  unless $use_keystore {
    file { '/etc/cyb3rhq-dashboard/opensearch_dashboards.keystore':
      ensure  => absent,
      require => Package['cyb3rhq-dashboard'],
      before  => Service['cyb3rhq-dashboard'],
    }
  }

  service { 'cyb3rhq-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    name       => $dashboard_service,
  }
}
