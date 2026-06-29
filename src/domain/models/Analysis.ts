export type AnalysisScore='good'|'warning'|'bad';
export type AnalysisMessage={id:string; level:'info'|'warning'|'error'; text:string};
export type CollisionPair={aId:string;bId:string}; export type BlockedOpening={openingId:string; furnitureId:string}; export type BlockedPath={pathId:string; furnitureId:string};
export type AnalysisResult={score:AnalysisScore; messages:AnalysisMessage[]; collisions:CollisionPair[]; blockedOpenings:BlockedOpening[]; blockedPaths:BlockedPath[]};
