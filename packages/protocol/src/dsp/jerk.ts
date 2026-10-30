import type { ResampledSeries } from './resample.js';
export interface JerkBounds { maxExcessKurtosis: number }
export const DEFAULT_JERK_BOUNDS: JerkBounds = { maxExcessKurtosis: 100 };
export function thirdDifference(a: Float64Array): Float64Array { const o=new Float64Array(Math.max(0,a.length-3)); for(let i=0;i<o.length;i++) o[i]=a[i+3]!-3*a[i+2]!+3*a[i+1]!-a[i]!; return o; }
function kurt(a: number[]): number { if(a.length<4)return 0; const m=a.reduce((x,y)=>x+y,0)/a.length; const v=a.reduce((x,y)=>x+(y-m)**2,0)/a.length; if(v<=1e-12)return 0; return a.reduce((x,y)=>x+(y-m)**4,0)/a.length/(v*v)-3; }
export function analyzeJerk(series: ResampledSeries[], _bounds=DEFAULT_JERK_BOUNDS): { maxExcessKurtosis:number } { let m=-Infinity; for(const s of series){const dx=thirdDifference(s.x),dy=thirdDifference(s.y),j=[] as number[]; for(let i=0;i<Math.min(dx.length,dy.length);i++)j.push(Math.hypot(dx[i]!,dy[i]!)); m=Math.max(m,kurt(j));} return {maxExcessKurtosis:Number.isFinite(m)?m:0}; }
