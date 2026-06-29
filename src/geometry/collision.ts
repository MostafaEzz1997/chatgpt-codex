import { Room } from '../domain/models/Room'; import { Furniture } from '../domain/models/Furniture'; import { compoundIntersectsFurniture, getFurnitureParts } from './compoundShape';
export const furnitureCollides=(a:Furniture,b:Furniture)=>a.metadata?.nonColliding||b.metadata?.nonColliding?false:compoundIntersectsFurniture(a,b);
export const getCollisionPairs=(room:Room)=>room.furniture.flatMap((a,i)=>room.furniture.slice(i+1).filter(b=>furnitureCollides(a,b)).map(b=>({aId:a.id,bId:b.id})));
export const isFurnitureInsideRoom=(room:Room,f:Furniture)=>getFurnitureParts(f).every(p=>p.xCm>=0&&p.yCm>=0&&p.xCm+p.widthCm<=room.widthCm&&p.yCm+p.heightCm<=room.heightCm);
