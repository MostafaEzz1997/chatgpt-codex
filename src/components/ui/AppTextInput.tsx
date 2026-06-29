import React from 'react'; import { TextInput, StyleSheet, TextInputProps } from 'react-native';
export default function AppTextInput(p:TextInputProps){return <TextInput {...p} style={[s.input,p.style]} placeholderTextColor="#8a8f98"/>}
const s=StyleSheet.create({input:{borderWidth:1,borderColor:'#d6d3cc',borderRadius:10,padding:10,margin:4,backgroundColor:'#fff'}});
