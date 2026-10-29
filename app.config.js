// Dynamic Expo config — reads the web base path from the environment.
//
//   BLUEWINK_BASE_PATH=/bil/kona npx expo export --platform web
//
// Defaults to "/" (served at the domain root) when unset.

const basePath = process.env.BLUEWINK_BASE_PATH?.trim().replace(/\/+$/, '') || ''

export default {
  expo: {
    experiments: {
      baseUrl: basePath,
    },
  },
}
