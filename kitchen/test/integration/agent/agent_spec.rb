control 'cyb3rhq-agent' do
  title 'Cyb3rhq agent tests'
  describe 'Checks Cyb3rhq agent correct version, services and daemon ownership'

  describe package('cyb3rhq-agent') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '5.0.0-1' }
  end

  describe service('cyb3rhq-agent') do
    it { is_expected.to be_installed }
    it { is_expected.to be_enabled }
    it { is_expected.to be_running }
  end

  # Verifying daemons
  cyb3rhq_daemons = {
    'cyb3rhq-agentd' => 'cyb3rhq',
    'cyb3rhq-execd' => 'root',
    'cyb3rhq-modulesd' => 'root',
    'cyb3rhq-syscheckd' => 'root',
    'cyb3rhq-logcollector' => 'root'
  }

  cyb3rhq_daemons.each do |key, value|
    describe processes(key) do
      its('users') { is_expected.to eq [value] }
    end
  end
end
