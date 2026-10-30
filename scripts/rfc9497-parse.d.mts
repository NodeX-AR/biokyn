export interface RfcVector { Input: string; Blind: string; BlindedElement: string; EvaluationElement: string; Output: string; Proof?: string; ProofRandomScalar?: string }
export interface RfcVectorSet { mode: number; seed: string; keyInfo: string; skSm: string; pkSm?: string; vectors: RfcVector[] }
export function parseRfc9497(text: string): RfcVectorSet[];
