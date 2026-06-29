import { Project } from '../domain/models/Project';
export const validateProject=(v:unknown):v is Project=>{const p=v as Project;return !!p&&typeof p.id==='string'&&typeof p.name==='string'&&Array.isArray(p.rooms)&&p.rooms.every(r=>typeof r.widthCm==='number'&&typeof r.heightCm==='number'&&Array.isArray(r.furniture)&&Array.isArray(r.openings)&&Array.isArray(r.walkingPaths));};
export const validateProjectArray=(v:unknown):v is Project[]=>Array.isArray(v)&&v.every(validateProject);
