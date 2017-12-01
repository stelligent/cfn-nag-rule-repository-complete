require 'cfn-nag/violation'
require 'cfn-nag/custom_rules/base'

class RdsDbInstanceStorageEncryptedRule < BaseRule
  def rule_text
    'RDS DBInstance does not have StorageEncrypted set to true'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'F8000000'
  end

  def audit_impl(cfn_model)
    violating_instances = cfn_model.resources_by_type('AWS::RDS::DBInstance').select do |instance|
      instance.storageEncrypted.nil? || instance.storageEncrypted.to_s == 'false'
    end

    # only return the logic resource ids
    violating_instances.map { |violating_instance| violating_instance.logical_resource_id }
  end
end
