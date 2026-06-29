import { WalkingPath } from '../domain/models/WalkingPath'; import { Furniture, Rect } from '../domain/models/Furniture'; import { Room } from '../domain/models/Room'; import { compoundIntersectsRect } from './compoundShape';
export type Point={xCm:number;yCm:number};
export const distancePointToSegment=(p:Point,a:Point,b:Point)=>{const dx=b.xCm-a.xCm,dy=b.yCm-a.yCm,l2=dx*dx+dy*dy;if(!l2)return Math.hypot(p.xCm-a.xCm,p.yCm-a.yCm);const t=Math.max(0,Math.min(1,((p.xCm-a.xCm)*dx+(p.yCm-a.yCm)*dy)/l2));return Math.hypot(p.xCm-(a.xCm+t*dx),p.yCm-(a.yCm+t*dy));};
export const pathBoundingCorridor=(p:WalkingPath):Rect=>({xCm:Math.min(p.x1Cm,p.x2Cm)-p.widthCm/2,yCm:Math.min(p.y1Cm,p.y2Cm)-p.widthCm/2,widthCm:Math.abs(p.x2Cm-p.x1Cm)+p.widthCm,heightCm:Math.abs(p.y2Cm-p.y1Cm)+p.widthCm});
export const pathIntersectsFurniture=(p:WalkingPath,f:Furniture)=>compoundIntersectsRect(f,pathBoundingCorridor(p));
export const pathBlockedByFurniture=(p:WalkingPath,room:Room)=>room.furniture.find(f=>!f.metadata?.nonColliding&&pathIntersectsFurniture(p,f));
