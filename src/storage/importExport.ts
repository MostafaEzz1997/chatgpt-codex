import { Project } from '../domain/models/Project'; import { validateProject } from '../planner/validation';
export const exportProjectJson=(project:Project)=>JSON.stringify({schemaVersion:1,project},null,2);
export const importProjectJson=(json:string):Project=>{const parsed=JSON.parse(json) as {project?:unknown}; const candidate=parsed.project ?? parsed; if(!validateProject(candidate)) throw new Error('Invalid Room Layout Studio project JSON'); return candidate;};
