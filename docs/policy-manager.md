# PolicyManager Usage Guide

## Overview

The `PolicyManager` is the Policy Administration Point (PAP) component of TaintGate. It manages security policies, resolves policy conflicts using "Most Restrictive Wins" (MRW) logic, and provides policy versioning and hot-reload capabilities.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Configuration](#configuration)
- [Policy File Format](#policy-file-format)
- [Policy Resolution (MRW)](#policy-resolution-mrw)
- [Hot-Reload](#hot-reload)
- [Policy Versioning](#policy-versioning)
- [Integration Examples](#integration-examples)
- [Best Practices](#best-practices)
- [Error Handling](#error-handling)

---

## Basic Usage

### Simple Example

```typescript
import { PolicyManager } from '@taintgate/core';

// Create a PolicyManager with default configuration
const policyManager = new PolicyManager({
  policyPath: './policies/default.json',
  enableHotReload: true,
});

// Load policies from file
await policyManager.loadPolicies();

// Get resolved policy for a specific context
const resolution = await policyManager.getResolvedPolicy('tenant-A', 'database:read_row');

console.log('Resolved thresholds:', resolution.thresholds);
console.log('Resolved weights:', resolution.weights);
console.log('Action override:', resolution.actionOverride);
```

### With Custom Configuration

```typescript
const policyManager = new PolicyManager({
  policyPath: './policies/production.json',
  enableHotReload: true,
  reloadInterval: 30000, // Check every 30 seconds
  failClosed: true, // Use fail-closed defaults if file not found
  maxFileSize: 5 * 1024 * 1024, // 5MB limit
  maxHistorySize: 50, // Keep last 50 versions
});

await policyManager.loadPolicies();
```

---

## Configuration

### PolicyManagerConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `policyPath` | `string` | `'./policies/default.json'` | Path to policy configuration file (JSON) |
| `enableHotReload` | `boolean` | `false` | Enable automatic policy reload on file changes |
| `reloadInterval` | `number` | `60000` | Hot-reload check interval in milliseconds (min: 1000ms) |
| `failClosed` | `boolean` | `true` | Use fail-closed defaults when policy file not found |
| `maxFileSize` | `number` | `10485760` (10MB) | Maximum policy file size in bytes |
| `maxHistorySize` | `number` | `100` | Maximum number of policy versions to keep in history |

### Configuration Validation

The PolicyManager validates configuration on construction:

```typescript
// ❌ Invalid: reloadInterval too small
new PolicyManager({ reloadInterval: 500 }); 
// Throws: "reloadInterval must be at least 1000ms (1 second)"

// ❌ Invalid: maxFileSize must be positive
new PolicyManager({ maxFileSize: -1 }); 
// Throws: "maxFileSize must be greater than 0"

// ❌ Invalid: maxHistorySize must be at least 1
new PolicyManager({ maxHistorySize: 0 }); 
// Throws: "maxHistorySize must be at least 1"
```

---

## Policy File Format

### JSON Structure

```json
{
  "version": "1.0.0",
  "global": {
    "riskThresholds": {
      "allow": 0.3,
      "block": 0.7
    },
    "weights": {
      "sensitivity": 0.6,
      "exposure": 0.4
    },
    "actionOverride": null,
    "enabled": true
  },
  "tenants": {
    "tenant-A": {
      "riskThresholds": {
        "allow": 0.2,
        "block": 0.5
      },
      "weights": {
        "sensitivity": 0.7,
        "exposure": 0.3
      },
      "actionOverride": null,
      "enabled": true
    }
  },
  "tools": {
    "database:read_row": {
      "riskThresholds": {
        "allow": 0.3,
        "block": 0.7
      },
      "weights": {
        "sensitivity": 0.6,
        "exposure": 0.4
      },
      "actionOverride": "REDACT",
      "enabled": true
    }
  }
}
```

### Field Descriptions

#### Global Policy
- **`riskThresholds.allow`** (number, 0-1): Risk score below which requests are ALLOWED
- **`riskThresholds.block`** (number, 0-1): Risk score above which requests are BLOCKED
- **`weights.sensitivity`** (number, 0-1): Weight for sensitivity factor in risk calculation
- **`weights.exposure`** (number, 0-1): Weight for exposure factor in risk calculation
- **`actionOverride`** (`'ALLOW' | 'REDACT' | 'BLOCK' | null`): Force specific action regardless of risk score
- **`enabled`** (boolean): Whether this policy is active

#### Tenant Policies
- Same structure as global policy
- Overrides global policy for specific tenant
- Applied in addition to global policy (MRW resolution)

#### Tool Policies
- Same structure as global policy
- Overrides both global and tenant policies for specific tool
- Applied in addition to global/tenant policies (MRW resolution)

### Default Values

If fields are omitted, defaults are used:

```json
{
  "version": "1.0",
  "global": {
    // riskThresholds.allow defaults to 0.3
    // riskThresholds.block defaults to 0.7
    // weights.sensitivity defaults to 0.6
    // weights.exposure defaults to 0.4
    // enabled defaults to true
  }
}
```

### Minimal Policy File

```json
{
  "version": "1.0",
  "global": {}
}
```

This creates a policy with all default values.

---

## Policy Resolution (MRW)

The PolicyManager uses **Most Restrictive Wins (MRW)** logic to resolve conflicts between global, tenant, and tool policies.

### Resolution Rules

#### 1. Action Override Resolution
**Highest severity wins**: `BLOCK > REDACT > ALLOW`

```typescript
// Example: Global = ALLOW, Tenant = REDACT, Tool = BLOCK
// Result: BLOCK (highest severity)
const resolution = await policyManager.getResolvedPolicy('tenant-A', 'tool-1');
// resolution.actionOverride = 'BLOCK'
```

#### 2. Threshold Resolution
**Most restrictive (minimum values) wins**

```typescript
// Global: allow=0.3, block=0.7
// Tenant: allow=0.2, block=0.5
// Result: allow=0.2, block=0.5 (most restrictive)
```

#### 3. Weight Resolution
**Most restrictive (maximum values) wins, then normalized**

```typescript
// Global: sensitivity=0.6, exposure=0.4
// Tenant: sensitivity=0.8, exposure=0.2
// Result: sensitivity=0.8, exposure=0.4 (max values)
// If sum > 1.0, values are normalized
```

### Example: Multi-Level Policy Resolution

```typescript
// Policy file:
{
  "global": {
    "riskThresholds": { "allow": 0.3, "block": 0.7 },
    "actionOverride": "ALLOW"
  },
  "tenants": {
    "financial-services": {
      "riskThresholds": { "allow": 0.2, "block": 0.5 },
      "actionOverride": "REDACT"
    }
  },
  "tools": {
    "database:read_row": {
      "actionOverride": "BLOCK"
    }
  }
}

// Resolution for financial-services tenant, database:read_row tool:
const resolution = await policyManager.getResolvedPolicy(
  'financial-services',
  'database:read_row'
);

// Result:
// - actionOverride: 'BLOCK' (highest severity from tool policy)
// - thresholds.allow: 0.2 (minimum from tenant policy)
// - thresholds.block: 0.5 (minimum from tenant policy)
```

---

## Hot-Reload

### Enabling Hot-Reload

```typescript
const policyManager = new PolicyManager({
  policyPath: './policies/default.json',
  enableHotReload: true,
  reloadInterval: 30000, // Check every 30 seconds
});

await policyManager.loadPolicies();

// Policies will automatically reload when file changes
// Previous policy is preserved if reload fails (fail-safe)
```

### Manual Reload

```typescript
// Manually trigger reload
await policyManager.reloadPolicies();
```

### Hot-Reload Behavior

- **File Monitoring**: Checks file modification time at configured interval
- **Fail-Safe**: If reload fails, previous policy remains active
- **Thread-Safe**: Concurrent reloads are prevented
- **Error Handling**: Reload errors are logged but don't crash the system

### Example: Updating Policies Without Restart

```typescript
// 1. Initial load
await policyManager.loadPolicies();
console.log(policyManager.getPolicyVersion()); // "1.0"

// 2. Update policy file (e.g., via file editor or CI/CD)
// File: ./policies/default.json
// {
//   "version": "2.0",
//   "global": { "riskThresholds": { "allow": 0.2, "block": 0.6 } }
// }

// 3. Wait for hot-reload (or trigger manually)
await new Promise(resolve => setTimeout(resolve, 35000)); // Wait 35s
// OR
await policyManager.reloadPolicies();

// 4. New policy is active
console.log(policyManager.getPolicyVersion()); // "2.0"
```

---

## Policy Versioning

### Getting Current Version

```typescript
const version = policyManager.getPolicyVersion();
console.log(version); // "1.0.0" or "fail-closed-default"
```

### Policy History

```typescript
const history = policyManager.getPolicyHistory();

// Returns array of:
// [
//   {
//     version: "1.0",
//     loadedAt: Date,
//     description: "Loaded from ./policies/default.json"
//   },
//   {
//     version: "2.0",
//     loadedAt: Date,
//     description: "Loaded from ./policies/default.json"
//   }
// ]
```

### Rollback to Previous Version

```typescript
// Get history
const history = policyManager.getPolicyHistory();
console.log(history); // [{ version: "1.0", ... }, { version: "2.0", ... }]

// Rollback to version 1.0
await policyManager.rollbackPolicy('1.0');

// Policy is now restored to version 1.0
console.log(policyManager.getPolicyVersion()); // "1.0"

// New history entry created for rollback
const newHistory = policyManager.getPolicyHistory();
console.log(newHistory[newHistory.length - 1].description); 
// "Rollback to version 1.0"
```

---

## Integration Examples

### With RiskEvaluator

```typescript
import { PolicyManager } from '@taintgate/core';
import type { IRiskEvaluator } from '@taintgate/core';

// PolicyManager provides risk evaluation config
const policyManager = new PolicyManager({
  policyPath: './policies/default.json',
});

await policyManager.loadPolicies();

// Get risk evaluation configuration
const riskConfig = await policyManager.getRiskEvaluationConfig(
  'tenant-A',
  'database:read_row'
);

// riskConfig contains:
// {
//   weightSensitivity: 0.6,
//   weightExposure: 0.4,
//   thresholdAllow: 0.3,
//   thresholdBlock: 0.7,
//   enableTaintEvaluation: true
// }

// Use in RiskEvaluator
const riskEvaluator = new RiskEvaluator({
  policyManager, // RiskEvaluator pulls config from PolicyManager
  // ... other config
});
```

### With TaintGate

```typescript
import { TaintGate, PolicyManager, TaintRegistry } from '@taintgate/core';

const policyManager = new PolicyManager({
  policyPath: './policies/production.json',
  enableHotReload: true,
});

await policyManager.loadPolicies();

const mediator = new TaintGate({
  policyManager,
  riskEvaluator: new RiskEvaluator({ policyManager }),
  taintRegistry: new TaintRegistry(),
  // ... other dependencies
});

// TaintGate uses PolicyManager.getResolvedPolicy() internally
// to apply MRW conflict resolution
```

### Multi-Tenant Example

```typescript
const policyManager = new PolicyManager({
  policyPath: './policies/multi-tenant.json',
});

await policyManager.loadPolicies();

// Different tenants get different policies
const tenantAResolution = await policyManager.getResolvedPolicy('tenant-A');
const tenantBResolution = await policyManager.getResolvedPolicy('tenant-B');

// tenant-A might have stricter thresholds
console.log(tenantAResolution.thresholds.allow); // 0.2
console.log(tenantBResolution.thresholds.allow); // 0.3
```

---

## Best Practices

### 1. Policy File Organization

```
policies/
├── default.json          # Base policies
├── production.json        # Production-specific
├── staging.json           # Staging-specific
└── tenants/
    ├── financial-services.json
    └── healthcare.json
```

### 2. Version Management

Always include version in policy files:

```json
{
  "version": "1.2.3",
  "global": { ... }
}
```

Use semantic versioning:
- **Major**: Breaking changes (e.g., removed fields)
- **Minor**: New features (e.g., new tenant policies)
- **Patch**: Bug fixes (e.g., threshold adjustments)

### 3. Fail-Closed Defaults

Enable fail-closed mode for production:

```typescript
const policyManager = new PolicyManager({
  policyPath: './policies/production.json',
  failClosed: true, // ✅ Always use fail-closed in production
});
```

### 4. Hot-Reload in Production

Use hot-reload carefully in production:

```typescript
const policyManager = new PolicyManager({
  policyPath: './policies/production.json',
  enableHotReload: true,
  reloadInterval: 60000, // ✅ Longer interval in production (1 minute)
});
```

**Considerations:**
- Test policy changes in staging first
- Use version control for policy files
- Monitor policy reloads in logs
- Have rollback plan ready

### 5. Policy Validation

Validate policies before deployment:

```typescript
const policyManager = new PolicyManager();

// Load and validate
try {
  await policyManager.loadPolicies('./policies/new-policy.json');
  console.log('Policy valid!');
} catch (error) {
  console.error('Policy validation failed:', error);
  // Don't deploy invalid policies
}
```

### 6. Policy Testing

Test policy resolution:

```typescript
// Test MRW resolution
const resolution = await policyManager.getResolvedPolicy('tenant-A', 'tool-1');

// Verify expected values
expect(resolution.thresholds.allow).toBe(0.2);
expect(resolution.actionOverride).toBe('BLOCK');
```

---

## Error Handling

### Common Errors

#### 1. Policy File Not Found

```typescript
const policyManager = new PolicyManager({
  policyPath: './policies/missing.json',
  failClosed: false, // Will throw error
});

try {
  await policyManager.loadPolicies();
} catch (error) {
  console.error(error.message);
  // "Policy file not found: ./policies/missing.json"
}
```

**Solution**: Use `failClosed: true` to use defaults, or ensure file exists.

#### 2. Invalid JSON

```typescript
try {
  await policyManager.loadPolicies();
} catch (error) {
  console.error(error.message);
  // "Invalid JSON in policy file: ./policies/default.json. Error: ..."
}
```

**Solution**: Validate JSON syntax before loading.

#### 3. Invalid Policy Structure

```typescript
try {
  await policyManager.loadPolicies();
} catch (error) {
  console.error(error.message);
  // "Policy config must be an object"
  // OR
  // "global policy must be an object"
  // OR
  // "tenants must be an object"
}
```

**Solution**: Ensure policy file matches expected structure.

#### 4. Invalid Numeric Values

```typescript
try {
  await policyManager.loadPolicies();
} catch (error) {
  console.error(error.message);
  // "global.riskThresholds.allow must be a finite number, got NaN"
}
```

**Solution**: Ensure all numeric fields are valid numbers (not NaN, Infinity, or strings).

#### 5. Policy Validation Errors

```typescript
try {
  await policyManager.loadPolicies();
} catch (error) {
  console.error(error.message);
  // "Invalid global policy rule global-default: thresholdAllow (0.8) must be less than thresholdBlock (0.5)"
}
```

**Solution**: Fix policy validation errors (thresholds, weights, etc.).

### Error Recovery

The PolicyManager implements fail-safe behavior:

```typescript
// 1. Load initial policy
await policyManager.loadPolicies();
const version1 = policyManager.getPolicyVersion(); // "1.0"

// 2. Attempt reload with invalid policy
// (e.g., file becomes corrupted)
try {
  await policyManager.reloadPolicies();
} catch (error) {
  // Previous policy is preserved
  const version2 = policyManager.getPolicyVersion(); // Still "1.0"
  console.log('Reload failed, previous policy preserved');
}
```

---

## Health Checks

### Check Policy Manager Health

```typescript
const isHealthy = await policyManager.healthCheck();

if (!isHealthy) {
  // Policy manager is unhealthy
  // - Policies not loaded
  // - Policy file not accessible (if hot-reload enabled)
}
```

### Integration with Health Endpoints

```typescript
// Express.js example
app.get('/health', async (req, res) => {
  const policyHealthy = await policyManager.healthCheck();
  
  if (policyHealthy) {
    res.status(200).json({ status: 'healthy' });
  } else {
    res.status(503).json({ status: 'unhealthy' });
  }
});
```

---

## Performance Considerations

### Policy Resolution Caching

The PolicyManager does not cache resolved policies by default. For high-throughput scenarios, consider implementing caching at the application level:

```typescript
// Example: Simple cache implementation
const resolutionCache = new Map<string, PolicyResolution>();

async function getCachedResolvedPolicy(
  tenantId?: string,
  toolName?: string
): Promise<PolicyResolution> {
  const cacheKey = `${tenantId || 'global'}:${toolName || 'global'}`;
  
  if (resolutionCache.has(cacheKey)) {
    return resolutionCache.get(cacheKey)!;
  }
  
  const resolution = await policyManager.getResolvedPolicy(tenantId, toolName);
  resolutionCache.set(cacheKey, resolution);
  
  // Invalidate cache on policy reload
  policyManager.on('reload', () => resolutionCache.clear());
  
  return resolution;
}
```

### Policy File Size

Keep policy files reasonably sized:
- **Recommended**: < 1MB
- **Maximum**: 10MB (configurable)
- **Best Practice**: Split large policies into tenant-specific files

---

## Complete Example

```typescript
import { PolicyManager } from '@taintgate/core';

async function setupPolicyManager() {
  // 1. Create PolicyManager
  const policyManager = new PolicyManager({
    policyPath: './policies/production.json',
    enableHotReload: true,
    reloadInterval: 60000, // 1 minute
    failClosed: true,
    maxFileSize: 5 * 1024 * 1024, // 5MB
    maxHistorySize: 50,
  });

  // 2. Load initial policies
  try {
    await policyManager.loadPolicies();
    console.log('Policies loaded:', policyManager.getPolicyVersion());
  } catch (error) {
    console.error('Failed to load policies:', error);
    // With failClosed: true, defaults are used
  }

  // 3. Get resolved policy for context
  const resolution = await policyManager.getResolvedPolicy(
    'tenant-A',
    'database:read_row'
  );

  console.log('Resolved policy:', {
    thresholds: resolution.thresholds,
    weights: resolution.weights,
    actionOverride: resolution.actionOverride,
    policyVersion: resolution.policyVersion,
  });

  // 4. Monitor health
  setInterval(async () => {
    const healthy = await policyManager.healthCheck();
    if (!healthy) {
      console.warn('Policy manager unhealthy');
    }
  }, 30000); // Check every 30 seconds

  // 5. Cleanup on shutdown
  process.on('SIGTERM', () => {
    policyManager.destroy();
  });

  return policyManager;
}

// Usage
const policyManager = await setupPolicyManager();
```

---

## API Reference

### Methods

#### `loadPolicies(configPath?: string): Promise<void>`
Load policies from configuration file.

#### `getResolvedPolicy(tenantId?: string, toolName?: string): Promise<PolicyResolution>`
Get resolved policy for a specific context using MRW logic.

#### `getRiskEvaluationConfig(tenantId?: string, toolName?: string): Promise<RiskEvaluationConfig>`
Get risk evaluation configuration for a context.

#### `reloadPolicies(): Promise<void>`
Hot-reload policies without service restart.

#### `getPolicyVersion(): string`
Get current policy version.

#### `getPolicyHistory(): Array<{version: string, loadedAt: Date, description?: string}>`
Get policy history for rollback scenarios.

#### `rollbackPolicy(version: string): Promise<void>`
Rollback to a previous policy version.

#### `validatePolicy(rule: PolicyRule): {valid: boolean, errors: string[]}`
Validate a policy rule.

#### `healthCheck(): Promise<boolean>`
Health check for policy management system.

#### `destroy(): void`
Cleanup resources (stops hot-reload timer).

---

## See Also

- [ARCHITECTURE.md](./ARCHITECTURE.md) - Architecture overview
- [PENDING_IMPLEMENTATIONS.md](./PENDING_IMPLEMENTATIONS.md) - Implementation status
- [README.md](./README.md) - Project overview
- [examples/policy-example.json](./examples/policy-example.json) - Sample policy file
- [examples/policy-manager-example.ts](./examples/policy-manager-example.ts) - Complete usage example

