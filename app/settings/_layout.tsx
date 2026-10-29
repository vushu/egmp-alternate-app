import { Stack } from 'expo-router';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTheme } from '@/hooks/useTheme';

export default function SettingsLayout() {
  const t = useTheme();
  const insets = useSafeAreaInsets();
  return (
    <Stack
      screenOptions={{
        headerStyle: { backgroundColor: t.surface, height: 56 + insets.top } as any,
        headerTitleStyle: { fontWeight: '600', fontSize: 18, marginTop: insets.top } as any,
        headerShadowVisible: false,
      }}>
      <Stack.Screen name="index" options={{ title: 'Settings' }} />
      <Stack.Screen name="preferences" options={{ title: 'Preferences' }} />
      <Stack.Screen name="connection" options={{ title: 'Vehicle & Connection' }} />
    </Stack>
  );
}
