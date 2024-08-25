control 'cyb3rhq-manager' do
  title 'Cyb3rhq manager tests'
  describe 'Checks Cyb3rhq manager correct version, services and daemon ownership'

  describe package('cyb3rhq-manager') do
    it { is_expected.to be_installed }
    its('version') { is_expected.to eq '5.0.0-1' }
  end

  # Verifying service
  describe service('cyb3rhq-manager') do
    it { is_expected.to be_installed }
    it { is_expected.to be_enabled }
    it { is_expected.to be_running }
  end

  # Verifying daemons
  cyb3rhq_daemons = {
    'cyb3rhq-authd' => 'root',
    'cyb3rhq-execd' => 'root',
    'cyb3rhq-analysisd' => 'cyb3rhq',
    'cyb3rhq-syscheckd' => 'root',
    'cyb3rhq-remoted' => 'cyb3rhq',
    'cyb3rhq-logcollector' => 'root',
    'cyb3rhq-monitord' => 'cyb3rhq',
    'cyb3rhq-db' => 'cyb3rhq',
    'cyb3rhq-modulesd' => 'root',
  }

  cyb3rhq_daemons.each do |key, value|
    describe processes(key) do
      its('users') { is_expected.to eq [value] }
    end
  end
end
