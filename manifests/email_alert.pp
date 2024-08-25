# Copyright (C) 2015, Cyb3rhq Inc.
# Define an email alert
define cyb3rhq::email_alert(
  $alert_email,
  $alert_group    = false,
  $target_arg     = 'manager_ossec.conf',
  $level          = false,
  $event_location = false,
  $format         = false,
  $rule_id        = false,
  $do_not_delay   = false,
  $do_not_group   = false
) {
  require cyb3rhq::params_manager

  concat::fragment { $name:
    target  => $target_arg,
    order   => 66,
    content => template('cyb3rhq/fragments/_email_alert.erb'),
  }
}
