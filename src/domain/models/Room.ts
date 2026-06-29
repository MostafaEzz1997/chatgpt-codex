import { Furniture } from './Furniture'; import { Opening } from './Opening'; import { WalkingPath } from './WalkingPath';
export type Room = { id:string; name:string; widthCm:number; heightCm:number; furniture:Furniture[]; openings:Opening[]; walkingPaths:WalkingPath[]; notes?:string };
