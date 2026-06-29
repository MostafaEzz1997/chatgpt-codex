# Room Layout Studio

Professional mobile-native 2D room and furniture planner built with Expo, React Native, TypeScript, React Native Skia, Gesture Handler, Reanimated, Zustand, and local persistence.

## Sprint 1 Scope

Implemented Sprint 1 focuses only on a professional 2D planner. It intentionally excludes camera, 3D, AR, AI scanning, photo extraction, cloud sync, auth, payments, marketplaces, and backend services.

## Features

- Project CRUD: create, rename, duplicate, delete, and open projects.
- Room CRUD: create, rename, duplicate, delete, switch rooms, and edit dimensions in centimeters.
- Default sample project: **Dar Misr Flat Layout** with a **Reception** room, doors, corridor, windows, furniture, and a walking path.
- Furniture library with living, dining, bedroom, utility, custom furniture, structural cutout, and true compound L-shaped presets.
- Canvas rendering isolated under `src/canvas` using React Native Skia primitives.
- Touch selection, pan, pinch zoom, drag selected furniture/openings/paths.
- Furniture actions: rotate, resize, duplicate, delete, lock, unlock.
- Opening actions: add, select, move along wall, edit type/keep-clear, delete.
- Walking path actions: add, select, move, edit width, delete.
- Planner toggles: grid, snap-to-grid, grid size, furniture dimensions, clearances, walking paths.
- Pure TypeScript geometry for rectangles, compound shapes, collisions, clearances, hit testing, and walking paths.
- Room analysis for collisions, outside bounds, blocked keep-clear openings, blocked paths, dining clearance warnings, and structural cutouts.
- Local persistence behind `projectRepository` with safe fallback to the default project.
- JSON import/export helpers with validation.
- Image export abstraction placeholder (`exportRoomImageAsync`) ready to wire to a Skia snapshot in a device build.

## Install

```bash
npm install
```

> Note: this environment returned HTTP 403 for scoped npm packages such as `@react-native-async-storage/async-storage`. On a normal Expo development machine, run the command above. If your registry blocks scoped packages, configure your npm registry/proxy first.

## Run

```bash
npm run start
npm run android
npm run ios
```

## Test and type-check

```bash
npm run typecheck
npm run test
```

The geometry tests live in `src/tests` and cover rectangle operations, compound L-shape hit-testing/collision, walking paths, blocked openings, analysis score states, and JSON import validation.

## Build

```bash
npx expo prebuild
npx expo run:android
```

For production builds, use EAS Build after configuring your Expo account:

```bash
npx eas build --platform android
```


## Build Android APK with EAS

This repository includes `eas.json` with two Android build profiles:

- `preview`: internal distribution and `android.buildType: apk` for a directly installable APK.
- `production`: Android App Bundle (`app-bundle`) for Play Store style release builds.

Use these commands on a machine with working npm registry access and an Expo account:

```bash
npx eas-cli@latest login
npx eas-cli@latest build:configure
npx eas-cli@latest build -p android --profile preview
```

The preview build is the one to use when you need a downloadable APK for Android testing. The production profile builds an Android App Bundle.

A GitHub Actions fallback workflow is available at `.github/workflows/android-apk.yml`. It checks out the repository, uses Node 20 and Java 17, runs `npm ci`, prebuilds Android with Expo, runs `./gradlew assembleRelease`, copies the APK to `build/room-layout-studio.apk`, and uploads that APK as a workflow artifact.

## Architecture

```text
src/
  app/
  navigation/
  screens/
  components/ui/
  components/planner/
  canvas/
  domain/models/
  geometry/
  planner/
  store/
  storage/
  theme/
  tests/
```

Architecture rules followed:

- Domain and geometry logic are pure TypeScript.
- Geometry, collision, clearance, validation, and hit-testing do not import React or React Native.
- Canvas rendering lives under `src/canvas`.
- State mutation goes through the Zustand planner store.
- Persistence is abstracted by `projectRepository`.
- Stored dimensions and coordinates are centimeters.
- Compound L-shaped furniture uses real shape parts for rendering, hit-testing, and collision.

## Acceptance Criteria Checklist

- [x] App structure and Expo TypeScript entry points are present.
- [x] Default Dar Misr Flat Layout project and Reception room are created.
- [x] Furniture library includes required presets and L-shaped compound furniture.
- [x] Add buttons and row tap both add furniture.
- [x] Furniture can be selected, dragged, rotated, resized, duplicated, locked/unlocked, and deleted.
- [x] Openings can be added, selected, moved, edited, and deleted.
- [x] Walking paths can be added, selected, moved, edited, and deleted.
- [x] Grid, dimensions, clearances, and walking path toggles are exposed.
- [x] Collision, blocked opening, and blocked path analysis is implemented.
- [x] L-shape hit-testing and collision use visible compound parts, not bounding box only.
- [x] Local persistence load/save is abstracted with default fallback.
- [x] JSON import/export helpers are implemented and validated.
- [x] Geometry tests are included.
- [x] TypeScript compilation passes in this repository with local ambient declarations used only because npm install was blocked.
- [ ] Full device verification and real Skia image snapshot export remain to complete after dependency installation on a normal Expo environment.

## Dependency rationale

- `@shopify/react-native-skia`: native 2D canvas rendering.
- `react-native-gesture-handler`: reliable touch gestures.
- `react-native-reanimated`: smooth gesture-driven transforms in production builds.
- `zustand`: small predictable app state store.
- `@react-native-async-storage/async-storage`: local project persistence abstraction for Sprint 1.
- `@react-navigation/native` and native stack: mobile navigation.
- `vitest`: fast pure TypeScript geometry/domain tests.
