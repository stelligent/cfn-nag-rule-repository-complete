require 'spec_helper'
require 'cfn-model'
require 'RdsDbInstanceStorageEncryptedRule'

describe RdsDbInstanceStorageEncryptedRule do
  context 'when RDS::DBInstance has unspecified StorageEncrypted' do
    it 'returns logical resource id for offending DbInstance' do
      # load the test template into a CfnModel object
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/rds_dbinstance/db_instance_no_storage_encrypted.yml')

      # instantiate the rule
      # invoke audit against the rule object with the load CfnModel object
      actual_logical_resource_ids = RdsDbInstanceStorageEncryptedRule.new.audit_impl cfn_model

      # measure our expectations
      expected_logical_resource_ids = %w(ReallyImportantDBInstance)

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end

  context 'when RDS::DBInstance has StorageEncrypted==false' do
    it 'returns logical resource id for offending DbInstance' do
      # load the test template into a CfnModel object
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/rds_dbinstance/db_instance_storage_encrypted_false.yml')

      # instantiate the rule
      # invoke audit against the rule object with the load CfnModel object
      actual_logical_resource_ids = RdsDbInstanceStorageEncryptedRule.new.audit_impl cfn_model

      # measure our expectations
      expected_logical_resource_ids = %w(ReallyImportantDBInstance)

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end

  context 'when RDS::DBInstance has StorageEncrypted==false string' do
    it 'returns logical resource id for offending DbInstance' do
      # load the test template into a CfnModel object
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/rds_dbinstance/db_instance_storage_encrypted_false_string.yml')

      # instantiate the rule
      # invoke audit against the rule object with the load CfnModel object
      actual_logical_resource_ids = RdsDbInstanceStorageEncryptedRule.new.audit_impl cfn_model

      # measure our expectations
      expected_logical_resource_ids = %w(ReallyImportantDBInstance)

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end

  context 'when RDS::DBInstance has StorageEncrypted==true' do
    it 'returns logical resource id for offending DbInstance' do
      # load the test template into a CfnModel object
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/rds_dbinstance/db_instance_storage_encrypted_true.yml')

      # instantiate the rule
      # invoke audit against the rule object with the load CfnModel object
      actual_logical_resource_ids = RdsDbInstanceStorageEncryptedRule.new.audit_impl cfn_model

      # measure our expectations
      expected_logical_resource_ids = %w()

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end

  context 'when RDS::DBInstance has StorageEncrypted==true string' do
    it 'returns logical resource id for offending DbInstance' do
      # load the test template into a CfnModel object
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/rds_dbinstance/db_instance_storage_encrypted_true_string.yml')

      # instantiate the rule
      # invoke audit against the rule object with the load CfnModel object
      actual_logical_resource_ids = RdsDbInstanceStorageEncryptedRule.new.audit_impl cfn_model

      # measure our expectations
      expected_logical_resource_ids = %w()

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end
end
