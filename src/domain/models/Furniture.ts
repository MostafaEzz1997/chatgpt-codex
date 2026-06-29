export type RotationDeg = 0 | 90 | 180 | 270;
export type Rect = { xCm: number; yCm: number; widthCm: number; heightCm: number };
export type Furniture = { id:string; type:string; category:string; name:string; xCm:number; yCm:number; widthCm:number; depthCm:number; rotationDeg:RotationDeg; color:string; shapeType:'rect'|'compound'; parts?:Rect[]; locked?:boolean; clearance?:{aroundCm?:number;frontCm?:number}; metadata?:Record<string, unknown> };
