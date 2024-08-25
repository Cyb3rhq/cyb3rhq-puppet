# Cyb3rhq Puppet module

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://cyb3rhq.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/cyb3rhq)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://cyb3rhq.ghcr.io/documentation)
[![Web](https://img.shields.io/badge/web-view-green.svg)](https://cyb3rhq.com)
![Kitchen tests for Cyb3rhq Puppet](https://github.com/cyb3rhq/cyb3rhq-puppet/workflows/Kitchen%20tests%20for%20Cyb3rhq%20Puppet/badge.svg)

This module installs and configure Cyb3rhq agent and manager.

## Documentation

* [Full documentation](http://cyb3rhq.ghcr.io/documentation)
* [Cyb3rhq Puppet module documentation](https://cyb3rhq.ghcr.io/documentation/current/deploying-with-puppet/index.html)
* [Puppet Forge](https://forge.puppetlabs.com/cyb3rhq/cyb3rhq)

## Directory structure

    cyb3rhq-puppet/
    ├── CHANGELOG.md
    ├── checksums.json
    ├── data
    │   └── common.yaml
    ├── files
    │   └── ossec-logrotate.te
    ├── Gemfile
    ├── kitchen
    │   ├── chefignore
    │   ├── clean.sh
    │   ├── Gemfile
    │   ├── hieradata
    │   │   ├── common.yaml
    │   │   └── roles
    │   │       └── default.yaml
    │   ├── kitchen.yml
    │   ├── manifests
    │   │   └── site.pp.template
    │   ├── Puppetfile
    │   ├── README.md
    │   ├── run.sh
    │   └── test
    │       └── integration
    │           ├── agent
    │           │   └── agent_spec.rb
    │           └── mngr
    │               └── manager_spec.rb
    ├── LICENSE.txt
    ├── manifests
    │   ├── activeresponse.pp
    │   ├── addlog.pp
    │   ├── agent.pp
    │   ├── audit.pp
    │   ├── certificates.pp
    │   ├── command.pp
    │   ├── dashboard.pp
    │   ├── email_alert.pp
    │   ├── filebeat_oss.pp
    │   ├── indexer.pp
    │   ├── init.pp
    │   ├── integration.pp
    │   ├── manager.pp
    │   ├── params_agent.pp
    │   ├── params_manager.pp
    │   ├── repo_elastic_oss.pp
    │   ├── repo.pp
    │   ├── reports.pp
    │   └── tests.pp
    ├── metadata.json
    ├── Rakefile
    ├── README.md
    ├── spec
    │   ├── classes
    │   │   ├── client_spec.rb
    │   │   ├── init_spec.rb
    │   │   └── server_spec.rb
    │   └── spec_helper.rb
    ├── templates
    │   ├── default_commands.erb
    │   ├── filebeat_oss_yml.erb
    │   ├── fragments
    │   │   ├── _activeresponse.erb
    │   │   ├── _auth.erb
    │   │   ├── _cluster.erb
    │   │   ├── _command.erb
    │   │   ├── _default_activeresponse.erb
    │   │   ├── _email_alert.erb
    │   │   ├── _integration.erb
    │   │   ├── _labels.erb
    │   │   ├── _localfile.erb
    │   │   ├── _localfile_generation.erb
    │   │   ├── _reports.erb
    │   │   ├── _rootcheck.erb
    │   │   ├── _ruleset.erb
    │   │   ├── _sca.erb
    │   │   ├── _syscheck.erb
    │   │   ├── _syslog_output.erb
    │   │   ├── _vulnerability_detection.erb
    │   │   ├── _vulnerability_indexer.erb
    │   │   ├── _wodle_cis_cat.erb
    │   │   ├── _wodle_openscap.erb
    │   │   ├── _wodle_osquery.erb
    │   │   └── _wodle_syscollector.erb
    │   ├── disabledlog4j_options.erb
    │   ├── local_decoder.xml.erb
    │   ├── local_rules.xml.erb
    │   ├── ossec_shared_agent.conf.erb
    │   ├── process_list.erb
    │   ├── cyb3rhq_agent.conf.erb
    │   ├── cyb3rhq_api_yml.erb
    │   ├── cyb3rhq_config_yml.erb
    │   ├── cyb3rhq_manager.conf.erb
    │   └── cyb3rhq_yml.erb
    └── VERSION

## Branches

* `master` branch contains the latest code, be aware of possible bugs on this branch.
* `stable` branch on correspond to the last Cyb3rhq-Puppet stable version.

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/cyb3rhq) or the [Cyb3rhq Slack community channel](https://cyb3rhq.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## Credits and thank you

This Puppet module has been authored by Nicolas Zin, and updated by Jonathan Gazeley and Michael Porter. Cyb3rhq has forked it with the purpose of maintaining it. Thank you to the authors for the contribution.

## License and copyright

CYB3RHQ
Copyright (C) 2015, Cyb3rhq Inc.  (License GPLv2)

## Web References

* [Cyb3rhq website](http://cyb3rhq.com)
