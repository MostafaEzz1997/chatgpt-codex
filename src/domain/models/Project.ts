import { Room } from './Room'; import { PlannerSettings } from './PlannerSettings';
export type Project = { id:string; name:string; createdAt:string; updatedAt:string; activeRoomId:string; rooms:Room[]; settings:PlannerSettings };
export type ProjectDocument = { schemaVersion:1; projects:Project[] };
