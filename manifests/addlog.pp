# Copyright (C) 2015, Cyb3rhq Inc.
#Define a log-file to add to ossec
define cyb3rhq::addlog(
  $logfile      = undef,
  $logtype      = 'syslog',
  $logcommand   = undef,
  $commandalias = undef,
  $frequency    = undef,
  $target_arg   = 'manager_ossec.conf',
) {
  require cyb3rhq::params_manager

  concat::fragment { "ossec.conf_localfile-${logfile}":
    target  => $target_arg,
    content => template('cyb3rhq/fragments/_localfile_generation.erb'),
    order   => 21,
  }

}
