import React from 'react'; import { Group, Line } from '@shopify/react-native-skia'; import { WalkingPath } from '../domain/models/WalkingPath';
export const RenderPaths=({paths}:{paths:WalkingPath[]})=><Group>{paths.map(p=><Line key={p.id} p1={{x:p.x1Cm,y:p.y1Cm}} p2={{x:p.x2Cm,y:p.y2Cm}} color="#22c55e88" strokeWidth={p.widthCm}/>)}</Group>;
