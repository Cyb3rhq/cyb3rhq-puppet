# Copyright (C) 2015, Cyb3rhq Inc.
# Cyb3rhq repository installation
class cyb3rhq::securityadmin (
  $indexer_security_init_lockfile = '/var/tmp/indexer-security-init.lock',
  $indexer_network_host = '127.0.0.1',
) {
  exec { 'Initialize the Opensearch security index in Cyb3rhq indexer':
    path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
    command => "/usr/share/cyb3rhq-indexer/bin/indexer-security-init.sh -ho ${indexer_network_host} && touch ${indexer_security_init_lockfile}",
    creates => $indexer_security_init_lockfile,
    require => Service['cyb3rhq-indexer'],
  }
}
