import { Rect } from '../domain/models/Furniture';
export type Point={xCm:number;yCm:number};
export const normalizeRect=(r:Rect):Rect=>({xCm:Math.min(r.xCm,r.xCm+r.widthCm),yCm:Math.min(r.yCm,r.yCm+r.heightCm),widthCm:Math.abs(r.widthCm),heightCm:Math.abs(r.heightCm)});
export const rectIntersects=(a:Rect,b:Rect):boolean=>{const x=normalizeRect(a),y=normalizeRect(b);return x.xCm < y.xCm+y.widthCm && x.xCm+x.widthCm > y.xCm && x.yCm < y.yCm+y.heightCm && x.yCm+x.heightCm > y.yCm};
export const rectContainsPoint=(r:Rect,p:Point):boolean=>{const n=normalizeRect(r);return p.xCm>=n.xCm&&p.xCm<=n.xCm+n.widthCm&&p.yCm>=n.yCm&&p.yCm<=n.yCm+n.heightCm};
export const clampRectInsideBounds=(r:Rect,b:Rect):Rect=>({...r,xCm:Math.min(Math.max(r.xCm,b.xCm),b.xCm+b.widthCm-r.widthCm),yCm:Math.min(Math.max(r.yCm,b.yCm),b.yCm+b.heightCm-r.heightCm)});
export const rectDistance=(a:Rect,b:Rect):number=>{const x=Math.max(b.xCm-(a.xCm+a.widthCm),a.xCm-(b.xCm+b.widthCm),0);const y=Math.max(b.yCm-(a.yCm+a.heightCm),a.yCm-(b.yCm+b.heightCm),0);return Math.hypot(x,y)};
export const rectCenter=(r:Rect):Point=>({xCm:r.xCm+r.widthCm/2,yCm:r.yCm+r.heightCm/2});
export const expandRect=(r:Rect,amountCm:number):Rect=>({xCm:r.xCm-amountCm,yCm:r.yCm-amountCm,widthCm:r.widthCm+amountCm*2,heightCm:r.heightCm+amountCm*2});
