export interface RawSample { t: number; x: number; y: number; }
export interface ResampleOptions { hz?: number; maxGapMs?: number; }
export interface ResampledSeries { t0: number; dtMs: number; fs: number; n: number; x: Float64Array; y: Float64Array; nativeRateHz: number; }
export type InterpolationMethod = 'linear';
export function splitAtGaps(samples: readonly RawSample[], maxGapMs = 250): RawSample[][] {
  const out: RawSample[][] = []; let cur: RawSample[] = [];
  for (const s of samples) { if (cur.length && s.t - cur[cur.length - 1]!.t > maxGapMs) { out.push(cur); cur = []; } cur.push(s); }
  if (cur.length) out.push(cur); return out;
}
export function normalizeSamples(samples: readonly RawSample[]): RawSample[] {
  return samples.filter(s => Number.isFinite(s.t) && Number.isFinite(s.x) && Number.isFinite(s.y)).sort((a,b)=>a.t-b.t);
}
export function resample(samples: readonly RawSample[], opt: ResampleOptions = {}): ResampledSeries | null {
  const a = normalizeSamples(samples); if (a.length < 4) return null;
  const hz = opt.hz ?? 100, dt = 1000 / hz, start = a[0]!.t, end = a[a.length-1]!.t;
  const n = Math.floor((end - start) / dt) + 1; if (n < 4) return null;
  const x = new Float64Array(n), y = new Float64Array(n); let j = 0;
  for (let i=0;i<n;i++) { const t=start+i*dt; while(j<a.length-2 && a[j+1]!.t<t) j++; const p=a[j]!, q=a[Math.min(j+1,a.length-1)]!; const f=q.t===p.t?0:Math.max(0,Math.min(1,(t-p.t)/(q.t-p.t))); x[i]=p.x+(q.x-p.x)*f; y[i]=p.y+(q.y-p.y)*f; }
  const native = (a.length-1)*1000/Math.max(1,a[a.length-1]!.t-a[0]!.t);
  return {t0:start,dtMs:dt,fs:hz,n,x,y,nativeRateHz:native};
}
export function resampleSegments(samples: readonly RawSample[], opt: ResampleOptions = {}): ResampledSeries[] { return splitAtGaps(samples,opt.maxGapMs ?? 250).map(s=>resample(s,opt)).filter((x): x is ResampledSeries=>x!==null); }
