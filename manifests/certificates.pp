# Copyright (C) 2015, Cyb3rhq Inc.
# Cyb3rhq repository installation
class cyb3rhq::certificates (
  $cyb3rhq_repository = 'packages.wazuh.com',
  $cyb3rhq_version = '4.8',
  $indexer_certs = [],
  $manager_certs = [],
  $manager_master_certs = [],
  $manager_worker_certs = [],
  $dashboard_certs = []
) {
  file { 'Configure Cyb3rhq Certificates config.yml':
    owner   => 'root',
    path    => '/tmp/config.yml',
    group   => 'root',
    mode    => '0640',
    content => template('cyb3rhq/cyb3rhq_config_yml.erb'),
  }

  file { '/tmp/cyb3rhq-certs-tool.sh':
    ensure => file,
    source => "https://${cyb3rhq_repository}/${cyb3rhq_version}/cyb3rhq-certs-tool.sh",
    owner  => 'root',
    group  => 'root',
    mode   => '0740',
  }

  exec { 'Create Cyb3rhq Certificates':
    path    => '/usr/bin:/bin',
    command => 'bash /tmp/cyb3rhq-certs-tool.sh --all',
    creates => '/tmp/cyb3rhq-certificates',
    require => [
      File['/tmp/cyb3rhq-certs-tool.sh'],
      File['/tmp/config.yml'],
    ],
  }
  file { 'Copy all certificates into module':
    ensure => 'directory',
    source => '/tmp/cyb3rhq-certificates/',
    recurse => 'remote',
    path => '/etc/puppetlabs/code/environments/production/modules/archive/files/',
    owner => 'root',
    group => 'root',
    mode  => '0755',
  }
}
