/**
 * PolicyManager Usage Example
 * 
 * This example demonstrates how to use the PolicyManager component
 * for managing security policies in MCP-Shield.
 * 
 * @see POLICY_MANAGER_USAGE.md for comprehensive documentation
 */

import { PolicyManager } from '../src/core/PolicyManager';

async function main() {
  // 1. Create PolicyManager with configuration
  const policyManager = new PolicyManager({
    policyPath: './examples/policy-example.json',
    enableHotReload: true,
    reloadInterval: 30000, // Check every 30 seconds
    failClosed: true,
    maxFileSize: 10 * 1024 * 1024, // 10MB
    maxHistorySize: 50,
  });

  // 2. Load policies
  try {
    await policyManager.loadPolicies();
    console.log('✅ Policies loaded successfully');
    console.log('   Version:', policyManager.getPolicyVersion());
  } catch (error) {
    console.error('❌ Failed to load policies:', error);
    process.exit(1);
  }

  // 3. Get resolved policy for different contexts
  console.log('\n📋 Policy Resolution Examples:\n');

  // Example 1: Global policy (no tenant/tool)
  const globalResolution = await policyManager.getResolvedPolicy();
  console.log('Global Policy:');
  console.log('  Thresholds:', globalResolution.thresholds);
  console.log('  Weights:', globalResolution.weights);
  console.log('  Applied Policies:', globalResolution.appliedPolicies);

  // Example 2: Tenant-specific policy
  const tenantResolution = await policyManager.getResolvedPolicy('financial-services');
  console.log('\nFinancial Services Tenant:');
  console.log('  Thresholds:', tenantResolution.thresholds);
  console.log('  Weights:', tenantResolution.weights);
  console.log('  Applied Policies:', tenantResolution.appliedPolicies);

  // Example 3: Tool-specific policy
  const toolResolution = await policyManager.getResolvedPolicy(undefined, 'database:read_row');
  console.log('\nDatabase Read Tool:');
  console.log('  Action Override:', toolResolution.actionOverride);
  console.log('  Applied Policies:', toolResolution.appliedPolicies);

  // Example 4: Combined (tenant + tool)
  const combinedResolution = await policyManager.getResolvedPolicy(
    'financial-services',
    'database:read_row'
  );
  console.log('\nFinancial Services + Database Read:');
  console.log('  Action Override:', combinedResolution.actionOverride);
  console.log('  Thresholds:', combinedResolution.thresholds);
  console.log('  Applied Policies:', combinedResolution.appliedPolicies);

  // 4. Get risk evaluation configuration
  const riskConfig = await policyManager.getRiskEvaluationConfig(
    'financial-services',
    'database:read_row'
  );
  console.log('\n📊 Risk Evaluation Config:');
  console.log('  Weight Sensitivity:', riskConfig.weightSensitivity);
  console.log('  Weight Exposure:', riskConfig.weightExposure);
  console.log('  Threshold Allow:', riskConfig.thresholdAllow);
  console.log('  Threshold Block:', riskConfig.thresholdBlock);

  // 5. Policy history
  const history = policyManager.getPolicyHistory();
  console.log('\n📜 Policy History:');
  history.forEach((entry, index) => {
    console.log(`  ${index + 1}. Version ${entry.version} - ${entry.loadedAt.toISOString()}`);
    if (entry.description) {
      console.log(`     ${entry.description}`);
    }
  });

  // 6. Health check
  const isHealthy = await policyManager.healthCheck();
  console.log('\n🏥 Health Check:', isHealthy ? '✅ Healthy' : '❌ Unhealthy');

  // 7. Cleanup on shutdown
  process.on('SIGTERM', () => {
    console.log('\n🛑 Shutting down...');
    policyManager.destroy();
    process.exit(0);
  });

  // 8. Example: Manual reload
  console.log('\n🔄 Manual Reload Example:');
  try {
    await policyManager.reloadPolicies();
    console.log('✅ Policies reloaded successfully');
    console.log('   New Version:', policyManager.getPolicyVersion());
  } catch (error) {
    console.error('❌ Reload failed:', error);
    console.log('   Previous policy preserved');
  }
}

// Run example
main().catch(console.error);

