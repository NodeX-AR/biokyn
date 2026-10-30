/**
 * Explainable risk aggregation for server-side policy decisions.
 *
 * This is a policy helper, not a trained classifier. Supply only evidence collected/validated by the
 * server. Browser-reported motion values are forgeable and must never be treated as authoritative facts.
 * Use `reasons` for internal audit logs; avoid exposing detailed signals to an unauthenticated caller,
 * where they become an evasion oracle. A score is a policy estimate, not a calibrated probability.
 */
export type RiskBand = 'low' | 'medium' | 'high';
export interface RiskEvidence { id: string; weight: number; source: 'server' | 'client-untrusted'; detail?: string }
export interface RiskAssessment { score: number; band: RiskBand; reasons: string[]; requiresStepUp: boolean; denyRecommended: boolean }
export interface RiskPolicy { stepUpAt?: number; denyAt?: number; maxClientContribution?: number }

export function assessRisk(evidence: readonly RiskEvidence[], policy: RiskPolicy = {}): RiskAssessment {
  const stepUpAt = policy.stepUpAt ?? 35;
  const denyAt = policy.denyAt ?? 75;
  const maxClientContribution = policy.maxClientContribution ?? 15;
  for (const [name, value] of Object.entries({ stepUpAt, denyAt, maxClientContribution })) {
    if (!Number.isFinite(value) || value < 0 || value > 100) throw new RangeError(`${name} must be from 0 to 100`);
  }
  if (stepUpAt > denyAt) throw new RangeError('stepUpAt must not exceed denyAt');
  let serverWeight = 0;
  let clientWeight = 0;
  const reasons: string[] = [];
  for (const item of evidence) {
    if (!item || typeof item.id !== 'string' || !/^[a-z0-9][a-z0-9_.:-]{0,79}$/i.test(item.id)) throw new TypeError('invalid evidence id');
    if (!Number.isFinite(item.weight) || item.weight < 0 || item.weight > 100) throw new RangeError('evidence weight must be from 0 to 100');
    if (item.source !== 'server' && item.source !== 'client-untrusted') throw new TypeError('invalid evidence source');
    if (item.source === 'server') serverWeight += item.weight;
    else clientWeight += item.weight;
    reasons.push(item.id);
  }
  // Client evidence is capped to prevent forgeable browser telemetry from dominating policy.
  const score = Math.min(100, serverWeight + Math.min(maxClientContribution, clientWeight));
  const band: RiskBand = score >= denyAt ? 'high' : score >= stepUpAt ? 'medium' : 'low';
  return { score, band, reasons: [...new Set(reasons)], requiresStepUp: score >= stepUpAt, denyRecommended: score >= denyAt };
}
