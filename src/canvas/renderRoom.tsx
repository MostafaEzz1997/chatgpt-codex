import React from 'react'; import { Rect } from '@shopify/react-native-skia'; import { Room } from '../domain/models/Room';
export const RenderRoom=({room}:{room:Room})=><><Rect x={0} y={0} width={room.widthCm} height={room.heightCm} color="#fffdfa"/><Rect x={0} y={0} width={room.widthCm} height={room.heightCm} color="transparent" style="stroke" strokeWidth={6}/></>;
