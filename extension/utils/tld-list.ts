export const TLD_RISK_SCORES: Record<string, number> = {
  tk: 1.0,
  ml: 1.0,
  ga: 0.95,
  cf: 0.95,
  gq: 0.9,
  xyz: 0.75,
  top: 0.7,
  click: 0.65,
  work: 0.6,
  fit: 0.55,
  rest: 0.55,
  buzz: 0.5
};

export function getTldRiskScore(tld: string): number {
  return TLD_RISK_SCORES[tld.toLowerCase()] ?? 0;
}
