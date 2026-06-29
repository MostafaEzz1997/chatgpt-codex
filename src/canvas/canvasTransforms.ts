import { Point } from '../geometry/rect'; export type CanvasTransform={scale:number;translateX:number;translateY:number};
export const worldToScreen=(p:Point,t:CanvasTransform)=>({x:p.xCm*t.scale+t.translateX,y:p.yCm*t.scale+t.translateY});
export const screenToWorld=(p:{x:number;y:number},t:CanvasTransform):Point=>({xCm:(p.x-t.translateX)/t.scale,yCm:(p.y-t.translateY)/t.scale});
