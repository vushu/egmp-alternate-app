// Theme preference store — 'auto' follows the OS setting, 'light'/'dark' force it.
// The preference is persisted inside the app config; this store mirrors it for
// synchronous access from useTheme() during render.

import { create } from 'zustand'
import { loadConfig, saveConfig } from '@/src/storage/configStore'
import type { ThemePreference } from '@/src/config/types'

interface ThemeState {
  preference: ThemePreference
  hydrated: boolean
  setPreference: (pref: ThemePreference) => Promise<void>
  hydrate: () => Promise<void>
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  preference: 'auto',
  hydrated: false,

  setPreference: async (pref) => {
    set({ preference: pref })
    // Persist inside the app config (creates one if none exists yet)
    const { loadConfig: load, saveConfig: save } = await import('@/src/storage/configStore')
    const config = await load()
    await save({ ...(config ?? { manufacturer: 'hyundai', auth: { username: '', password: '', pin: '', region: '' } as any }), themePreference: pref } as any)
  },

  hydrate: async () => {
    if (get().hydrated) return
    const config = await loadConfig()
    set({ preference: config?.themePreference ?? 'auto', hydrated: true })
  },
}))
