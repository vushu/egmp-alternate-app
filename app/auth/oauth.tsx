import React, { useRef, useCallback, useState } from 'react';
import { StyleSheet, ActivityIndicator, Platform, TextInput, TouchableOpacity } from 'react-native';
import { useRouter } from 'expo-router';
import { WebView, WebViewNavigation } from 'react-native-webview';

import { Text, View } from '@/components/Themed';
import { useTheme } from '@/hooks/useTheme';
import {
  getEuropeAuthUrls,
  storeWebviewAuthResult,
} from '@/src/api/regions/europe';
import { useCarStore } from '@/src/store/carStore';

export default function OAuthScreen() {
  const router = useRouter();
  const { bluelink, connect } = useCarStore();
  const handled = useRef(false);

  const manufacturer = bluelink?.getConfig().manufacturer ?? 'hyundai';
  const authUrls = getEuropeAuthUrls(manufacturer);

  if (!authUrls) {
    return (
      <View style={styles.center}>
        <Text>OAuth not required for this manufacturer.</Text>
      </View>
    );
  }

  const brandName = manufacturer.charAt(0).toUpperCase() + manufacturer.slice(1);

  const handleCallback = useCallback((url: string) => {
    if (handled.current) return;
    if (url.startsWith(authUrls.callbackUrl) && url.includes('code=')) {
      handled.current = true;
      console.log('[OAuth] Got callback with code');
      storeWebviewAuthResult(url).then(() => {
        router.back();
        const config = bluelink?.getConfig();
        if (config) {
          setTimeout(() => connect(config), 300);
        }
      });
    }
  }, [authUrls, router, bluelink, connect]);

  if (Platform.OS === 'web') {
    return (
      <WebOAuthScreen
        startUrl={authUrls.startUrl}
        brandName={brandName}
        onSubmit={(url) => handleCallback(url)}
      />
    );
  }

  return (
    <View style={styles.container}>
      <WebView
        source={{ uri: authUrls.startUrl }}
        style={styles.webview}
        userAgent="Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19"
        javaScriptEnabled
        domStorageEnabled
        thirdPartyCookiesEnabled
        sharedCookiesEnabled
        onShouldStartLoadWithRequest={(request) => {
          if (handled.current) return false;
          if (request.url.startsWith(authUrls.callbackUrl) && request.url.includes('code=')) {
            handleCallback(request.url);
            return false;
          }
          return true;
        }}
        onNavigationStateChange={(navState: WebViewNavigation) => {
          handleCallback(navState.url);
        }}
        startInLoadingState
        renderLoading={() => (
          <View style={styles.loading}>
            <ActivityIndicator size="large" />
            <Text style={styles.loadingText}>Loading login page...</Text>
          </View>
        )}
      />
    </View>
  );
}

// Web browsers can't embed Kia's login page (no CORS/X-Frame-Options), so we
// open it in a popup and ask the user to paste the final redirect URL back.
function WebOAuthScreen({ startUrl, brandName, onSubmit }: { startUrl: string; brandName: string; onSubmit: (url: string) => void }) {
  const t = useTheme();
  const [url, setUrl] = useState('');
  const [opened, setOpened] = useState(false);

  const openLogin = () => {
    window.open(startUrl, '_blank', 'width=480,height=800');
    setOpened(true);
  };

  const submit = () => {
    if (url.includes('code=')) {
      onSubmit(url.trim());
    }
  };

  return (
    <View style={[styles.center, { backgroundColor: t.surface }]}>
      <Text style={[styles.webTitle, { color: t.onSurface }]}>{brandName} Login</Text>
      <Text style={[styles.webText, { color: t.onSurfaceVariant }]}>
        Tap the button to open {brandName}'s login page in a new tab. After logging in,
        copy the full URL from the address bar (it contains a code) and paste it below.
      </Text>
      <TouchableOpacity
        style={[styles.webButton, { backgroundColor: t.primary }]}
        onPress={openLogin}>
        <Text style={[styles.webButtonText, { color: t.onPrimary }]}>Open {brandName} Login</Text>
      </TouchableOpacity>
      {opened && (
        <>
          <TextInput
            style={[
              styles.webInput,
              { backgroundColor: t.surfaceContainerHigh, color: t.onSurface, borderColor: t.outlineVariant },
            ]}
            value={url}
            onChangeText={setUrl}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="https://oneapp.kia.com/redirect?code=..."
            placeholderTextColor={t.outline}
            multiline
          />
          <TouchableOpacity
            style={[styles.webButton, { backgroundColor: t.primary }, !url.includes('code=') && styles.buttonDisabled]}
            onPress={submit}
            disabled={!url.includes('code=')}>
            <Text style={[styles.webButtonText, { color: t.onPrimary }]}>Complete Login</Text>
          </TouchableOpacity>
        </>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 20 },
  webview: { flex: 1 },
  webTitle: { fontSize: 22, fontWeight: '600', marginBottom: 8 },
  webText: { fontSize: 14, textAlign: 'center', marginBottom: 20, maxWidth: 480 },
  webButton: {
    borderRadius: 24,
    paddingHorizontal: 24,
    paddingVertical: 12,
    marginVertical: 8,
    alignItems: 'center',
  },
  webButtonText: { fontSize: 15, fontWeight: '600' },
  webInput: {
    borderWidth: 1,
    borderRadius: 8,
    padding: 12,
    marginVertical: 8,
    width: '100%',
    maxWidth: 480,
    minHeight: 72,
    fontSize: 13,
    textAlignVertical: 'top',
  },
  buttonDisabled: { opacity: 0.5 },
  loading: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: { marginTop: 12, fontSize: 14 },
});
