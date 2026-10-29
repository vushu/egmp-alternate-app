import { useColorScheme } from 'react-native'
import { md3 } from '@/constants/Colors'
import { useThemeStore } from '@/src/store/themeStore'

export type MD3Colors = typeof md3.dark

export function useTheme(): MD3Colors {
  const scheme = useColorScheme()
  const preference = useThemeStore((s) => s.preference)
  const effective = preference === 'auto' ? scheme : preference
  return effective === 'light' ? md3.light : md3.dark
}
