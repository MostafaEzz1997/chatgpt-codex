import React from 'react'; import { View, StyleSheet, ViewProps } from 'react-native';
export default function AppCard(p:ViewProps){return <View {...p} style={[s.card,p.style]}/>}
const s=StyleSheet.create({card:{backgroundColor:'#fffdfa',borderRadius:16,padding:12,margin:8,elevation:2}});
