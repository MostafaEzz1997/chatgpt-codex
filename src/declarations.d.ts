declare namespace React { type ReactNode=unknown; }
declare module 'react' { const React:any; export default React; export const useEffect:any; export const useMemo:any; export const useState:any; }
declare module 'react-native' { export const View:any; export const Text:any; export const ScrollView:any; export const Pressable:any; export const StyleSheet:any; export const Modal:any; export const TextInput:any; export type TextInputProps=any; export type ViewProps=any; }
declare module 'react-native-gesture-handler' { export const GestureHandlerRootView:any; export const Gesture:any; export const GestureDetector:any; }
declare module '@shopify/react-native-skia' { export const Canvas:any; export const Group:any; export const Rect:any; export const Line:any; }
declare module '@react-navigation/native' { export const NavigationContainer:any; }
declare module '@react-navigation/native-stack' { export function createNativeStackNavigator<T>():any; }
declare module '@react-native-async-storage/async-storage' { const AsyncStorage:{getItem:(k:string)=>Promise<string|null>;setItem:(k:string,v:string)=>Promise<void>;removeItem:(k:string)=>Promise<void>}; export default AsyncStorage; }
declare module 'zustand' { export function create<T>(fn:(set:any,get:any)=>T): any; }
declare module 'vitest' { export const describe:any; export const it:any; export const expect:any; }
declare namespace JSX { interface IntrinsicElements { [elemName: string]: any } }
