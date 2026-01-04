/**
 * Basic type tests to verify build and type system
 */

import { describe, it, expect } from '@jest/globals';
import {
  createRiskScore,
  clampRiskScore,
  SensitivityLevel,
  extractSensitivity,
  extractTrust,
  extractExposure,
  FailClosedDefaults,
} from '../types';

describe('Type System', () => {
  describe('RiskScore', () => {
    it('should create valid RiskScore', () => {
      const score = createRiskScore(0.5);
      expect(score).toBe(0.5);
    });

    it('should throw on invalid RiskScore', () => {
      expect(() => createRiskScore(1.5)).toThrow(RangeError);
      expect(() => createRiskScore(-0.1)).toThrow(RangeError);
    });

    it('should clamp RiskScore to valid range', () => {
      const clamped = clampRiskScore(1.5);
      expect(clamped).toBe(1.0);
      
      const clampedNegative = clampRiskScore(-0.5);
      expect(clampedNegative).toBe(0.0);
    });
  });

  describe('SensitivityLevel', () => {
    it('should have correct enum values', () => {
      expect(SensitivityLevel.Public).toBe(0.0);
      expect(SensitivityLevel.Internal).toBe(0.5);
      expect(SensitivityLevel.Confidential).toBe(1.0);
      expect(SensitivityLevel.Restricted).toBe(1.0);
    });
  });

  describe('Fail-Closed Defaults', () => {
    it('should have correct fail-closed values', () => {
      expect(FailClosedDefaults.TRUST).toBe(0);
      expect(FailClosedDefaults.SENSITIVITY).toBe(1.0);
      expect(FailClosedDefaults.EXPOSURE).toBe(1);
      expect(FailClosedDefaults.SENSITIVITY_LEVEL).toBe(SensitivityLevel.Restricted);
    });
  });

  describe('Extraction Functions', () => {
    it('should extract sensitivity with fail-closed default', () => {
      // Missing hint → maximum sensitivity
      const missing = extractSensitivity(undefined);
      expect(missing).toBe(1.0);

      // Valid hint
      const publicLevel = extractSensitivity({ sensitive: SensitivityLevel.Public });
      expect(publicLevel).toBe(0.0);

      const restrictedLevel = extractSensitivity({ sensitive: SensitivityLevel.Restricted });
      expect(restrictedLevel).toBe(1.0);
    });

    it('should extract trust with fail-closed default', () => {
      // Missing hint → untrusted
      const missing = extractTrust(undefined);
      expect(missing).toBe(0);

      // Trusted
      const trusted = extractTrust({ trusted: true });
      expect(trusted).toBe(1.0);

      // Untrusted
      const untrusted = extractTrust({ trusted: false });
      expect(untrusted).toBe(0);
    });

    it('should extract exposure with fail-closed default', () => {
      // Missing hint → maximum exposure
      const missing = extractExposure(undefined);
      expect(missing).toBe(1);

      // Closed-world
      const closed = extractExposure({ openWorld: false });
      expect(closed).toBe(0);

      // Open-world
      const open = extractExposure({ openWorld: true });
      expect(open).toBe(1);
    });
  });
});

