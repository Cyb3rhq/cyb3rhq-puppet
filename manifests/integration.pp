# Copyright (C) 2015, Cyb3rhq Inc.
#Define for a specific ossec integration
define cyb3rhq::integration(
  $hook_url = '',
  $api_key = '',
  $in_rule_id = '',
  $in_level = 7,
  $in_group = '',
  $in_location = '',
  $in_format = '',
  $in_max_log = '',
) {

  require cyb3rhq::params_manager

  concat::fragment { $name:
    target  => 'manager_ossec.conf',
    order   => 60,
    content => template('cyb3rhq/fragments/_integration.erb')
  }
}
