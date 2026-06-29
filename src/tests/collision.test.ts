import { describe,it,expect } from 'vitest'; import { furnitureCollides } from '../geometry/collision'; import { Furniture } from '../domain/models/Furniture';
const r=(id:string,x:number,y:number):Furniture=>({id,type:'r',category:'c',name:id,xCm:x,yCm:y,widthCm:100,depthCm:100,rotationDeg:0,color:'#000',shapeType:'rect'});
const l:Furniture={...r('l',0,0),widthCm:200,depthCm:200,shapeType:'compound',parts:[{xCm:0,yCm:0,widthCm:200,heightCm:50},{xCm:0,yCm:0,widthCm:50,heightCm:200}]};
describe('collision',()=>{it('rectangular furniture collision',()=>expect(furnitureCollides(r('a',0,0),r('b',50,50))).toBe(true));it('compound furniture collision',()=>expect(furnitureCollides(l,r('b',150,150))).toBe(false));});
