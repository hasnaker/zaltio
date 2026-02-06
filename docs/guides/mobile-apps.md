# Mobile App Integration Guide

Integrate Zalt.io with React Native, Flutter, and native iOS/Android apps.

## React Native

### Installation

```bash
npm install @zalt/auth-sdk
npm install @react-native-async-storage/async-storage
npm install react-native-keychain  # For secure storage
```

### Secure Storage Setup

```typescript
// lib/secureStorage.ts
import * as Keychain from 'react-native-keychain';

export const secureStorage = {
  async getItem(key: string): Promise<string | null> {
    try {
      const credentials = await Keychain.getGenericPassword({ service: key });
      return credentials ? credentials.password : null;
    } catch {
      return null;
    }
  },
  
  async setItem(key: string, value: string): Promise<void> {
    await Keychain.setGenericPassword(key, value, { service: key });
  },
  
  async removeItem(key: string): Promise<void> {
    await Keychain.resetGenericPassword({ service: key });
  }
};
```

### Auth Client Setup

```typescript
// lib/auth.ts
import { ZaltAuth } from '@zalt/auth-sdk';
import { secureStorage } from './secureStorage';

export const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  storage: secureStorage,
  autoRefresh: true
});
```

### Auth Context

```typescript
// contexts/AuthContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { auth } from '../lib/auth';

interface AuthContextType {
  user: any;
  loading: boolean;
  login: (email: string, password: string) => Promise<any>;
  loginWithBiometrics: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const currentUser = await auth.getCurrentUser();
      setUser(currentUser);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    const result = await auth.login({ email, password });
    if (!result.mfa_required) {
      setUser(result.user);
    }
    return result;
  };

  const loginWithBiometrics = async () => {
    // WebAuthn for biometric login
    const options = await auth.webauthn.getAuthenticationOptions({
      email: await secureStorage.getItem('last_email')
    });
    
    // Platform-specific biometric prompt
    const credential = await performBiometricAuth(options);
    
    const result = await auth.webauthn.authenticate(credential);
    setUser(result.user);
  };

  const logout = async () => {
    await auth.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, loginWithBiometrics, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext)!;
```

### Login Screen

```typescript
// screens/LoginScreen.tsx
import React, { useState } from 'react';
import { View, TextInput, TouchableOpacity, Text, Alert } from 'react-native';
import { useAuth } from '../contexts/AuthContext';
import * as LocalAuthentication from 'expo-local-authentication';

export function LoginScreen({ navigation }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, loginWithBiometrics } = useAuth();

  const handleLogin = async () => {
    setLoading(true);
    try {
      const result = await login(email, password);
      
      if (result.mfa_required) {
        navigation.navigate('MFA', { sessionId: result.mfa_session_id });
      }
    } catch (error: any) {
      Alert.alert('Error', error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleBiometricLogin = async () => {
    // Check biometric availability
    const hasHardware = await LocalAuthentication.hasHardwareAsync();
    const isEnrolled = await LocalAuthentication.isEnrolledAsync();
    
    if (!hasHardware || !isEnrolled) {
      Alert.alert('Biometrics not available');
      return;
    }
    
    try {
      await loginWithBiometrics();
    } catch (error: any) {
      Alert.alert('Biometric login failed', error.message);
    }
  };

  return (
    <View style={styles.container}>
      <TextInput
        placeholder="Email"
        value={email}
        onChangeText={setEmail}
        autoCapitalize="none"
        keyboardType="email-address"
      />
      
      <TextInput
        placeholder="Password"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
      />
      
      <TouchableOpacity onPress={handleLogin} disabled={loading}>
        <Text>{loading ? 'Signing in...' : 'Sign In'}</Text>
      </TouchableOpacity>
      
      <TouchableOpacity onPress={handleBiometricLogin}>
        <Text>Sign in with Face ID / Touch ID</Text>
      </TouchableOpacity>
    </View>
  );
}
```

### Biometric Registration

```typescript
// screens/BiometricSetupScreen.tsx
import React from 'react';
import { View, TouchableOpacity, Text, Alert } from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import { auth } from '../lib/auth';

export function BiometricSetupScreen() {
  const setupBiometrics = async () => {
    // Verify user with local biometrics first
    const result = await LocalAuthentication.authenticateAsync({
      promptMessage: 'Authenticate to enable biometric login',
      fallbackLabel: 'Use passcode'
    });
    
    if (!result.success) {
      Alert.alert('Authentication failed');
      return;
    }
    
    try {
      // Get WebAuthn registration options
      const options = await auth.webauthn.getRegistrationOptions();
      
      // Create credential (platform-specific)
      const credential = await createPlatformCredential(options);
      
      // Register with Zalt.io
      await auth.webauthn.register(credential, 'Mobile Device');
      
      Alert.alert('Success', 'Biometric login enabled!');
    } catch (error: any) {
      Alert.alert('Error', error.message);
    }
  };

  return (
    <View>
      <Text>Enable Face ID / Touch ID for faster login</Text>
      <TouchableOpacity onPress={setupBiometrics}>
        <Text>Enable Biometrics</Text>
      </TouchableOpacity>
    </View>
  );
}
```

## Flutter

### Dependencies

```yaml
# pubspec.yaml
dependencies:
  http: ^1.1.0
  flutter_secure_storage: ^9.0.0
  local_auth: ^2.1.6
  jwt_decoder: ^2.0.1
```

### Auth Service

```dart
// lib/services/auth_service.dart
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class AuthService {
  static const String baseUrl = 'https://api.zalt.io';
  static const String realmId = 'your-realm-id';
  
  final storage = const FlutterSecureStorage();
  
  Future<Map<String, dynamic>> login(String email, String password) async {
    final response = await http.post(
      Uri.parse('$baseUrl/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'realm_id': realmId,
        'email': email,
        'password': password,
      }),
    );
    
    final data = jsonDecode(response.body);
    
    if (response.statusCode != 200) {
      throw Exception(data['error']['message']);
    }
    
    if (data['mfa_required'] == true) {
      return data;
    }
    
    // Store tokens securely
    await storage.write(key: 'access_token', value: data['tokens']['access_token']);
    await storage.write(key: 'refresh_token', value: data['tokens']['refresh_token']);
    
    return data;
  }
  
  Future<void> logout() async {
    final token = await storage.read(key: 'access_token');
    
    if (token != null) {
      await http.post(
        Uri.parse('$baseUrl/logout'),
        headers: {'Authorization': 'Bearer $token'},
      );
    }
    
    await storage.deleteAll();
  }
  
  Future<String?> getAccessToken() async {
    final token = await storage.read(key: 'access_token');
    
    if (token == null) return null;
    
    // Check if expired
    final decoded = JwtDecoder.decode(token);
    final exp = DateTime.fromMillisecondsSinceEpoch(decoded['exp'] * 1000);
    
    if (exp.isBefore(DateTime.now())) {
      // Refresh token
      return await refreshToken();
    }
    
    return token;
  }
  
  Future<String?> refreshToken() async {
    final refreshToken = await storage.read(key: 'refresh_token');
    
    if (refreshToken == null) return null;
    
    final response = await http.post(
      Uri.parse('$baseUrl/refresh'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'refresh_token': refreshToken}),
    );
    
    if (response.statusCode != 200) {
      await storage.deleteAll();
      return null;
    }
    
    final data = jsonDecode(response.body);
    await storage.write(key: 'access_token', value: data['tokens']['access_token']);
    await storage.write(key: 'refresh_token', value: data['tokens']['refresh_token']);
    
    return data['tokens']['access_token'];
  }
}
```

### Biometric Auth

```dart
// lib/services/biometric_service.dart
import 'package:local_auth/local_auth.dart';

class BiometricService {
  final LocalAuthentication _localAuth = LocalAuthentication();
  
  Future<bool> isAvailable() async {
    final canCheck = await _localAuth.canCheckBiometrics;
    final isSupported = await _localAuth.isDeviceSupported();
    return canCheck && isSupported;
  }
  
  Future<bool> authenticate() async {
    try {
      return await _localAuth.authenticate(
        localizedReason: 'Authenticate to sign in',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );
    } catch (e) {
      return false;
    }
  }
}
```

## Native iOS (Swift)

### Auth Manager

```swift
// AuthManager.swift
import Foundation
import Security

class AuthManager {
    static let shared = AuthManager()
    
    private let baseURL = "https://api.zalt.io"
    private let realmId = "your-realm-id"
    
    func login(email: String, password: String) async throws -> LoginResult {
        let url = URL(string: "\(baseURL)/login")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body = [
            "realm_id": realmId,
            "email": email,
            "password": password
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthError.networkError
        }
        
        let result = try JSONDecoder().decode(LoginResponse.self, from: data)
        
        if httpResponse.statusCode != 200 {
            throw AuthError.invalidCredentials
        }
        
        if result.mfaRequired {
            return .mfaRequired(sessionId: result.mfaSessionId!)
        }
        
        // Store tokens in Keychain
        try KeychainManager.save(key: "access_token", value: result.tokens!.accessToken)
        try KeychainManager.save(key: "refresh_token", value: result.tokens!.refreshToken)
        
        return .success(user: result.user!)
    }
}

// KeychainManager.swift
class KeychainManager {
    static func save(key: String, value: String) throws {
        let data = value.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed
        }
    }
    
    static func get(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return value
    }
}
```

### Face ID / Touch ID

```swift
// BiometricAuth.swift
import LocalAuthentication

class BiometricAuth {
    func authenticate() async throws -> Bool {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw BiometricError.notAvailable
        }
        
        return try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Sign in to your account"
        )
    }
}
```

## Native Android (Kotlin)

### Auth Repository

```kotlin
// AuthRepository.kt
class AuthRepository(private val context: Context) {
    private val baseUrl = "https://api.zalt.io"
    private val realmId = "your-realm-id"
    private val client = OkHttpClient()
    
    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        "auth_prefs",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    
    suspend fun login(email: String, password: String): LoginResult = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("realm_id", realmId)
            put("email", email)
            put("password", password)
        }
        
        val request = Request.Builder()
            .url("$baseUrl/login")
            .post(body.toString().toRequestBody("application/json".toMediaType()))
            .build()
        
        val response = client.newCall(request).execute()
        val data = JSONObject(response.body?.string() ?: "")
        
        if (!response.isSuccessful) {
            throw AuthException(data.getJSONObject("error").getString("message"))
        }
        
        if (data.optBoolean("mfa_required")) {
            return@withContext LoginResult.MfaRequired(data.getString("mfa_session_id"))
        }
        
        val tokens = data.getJSONObject("tokens")
        saveTokens(tokens.getString("access_token"), tokens.getString("refresh_token"))
        
        return@withContext LoginResult.Success(parseUser(data.getJSONObject("user")))
    }
    
    private fun saveTokens(accessToken: String, refreshToken: String) {
        encryptedPrefs.edit()
            .putString("access_token", accessToken)
            .putString("refresh_token", refreshToken)
            .apply()
    }
}
```

### Biometric Prompt

```kotlin
// BiometricHelper.kt
class BiometricHelper(private val activity: FragmentActivity) {
    
    fun authenticate(onSuccess: () -> Unit, onError: (String) -> Unit) {
        val executor = ContextCompat.getMainExecutor(activity)
        
        val biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }
                
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }
            }
        )
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Sign in")
            .setSubtitle("Use your fingerprint or face to sign in")
            .setNegativeButtonText("Cancel")
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
}
```

## Security Best Practices

1. **Secure Storage** - Always use Keychain (iOS) or EncryptedSharedPreferences (Android)
2. **Certificate Pinning** - Pin Zalt.io's SSL certificate
3. **Biometric Binding** - Bind WebAuthn credentials to device biometrics
4. **Token Refresh** - Implement automatic token refresh
5. **Secure Communication** - Use HTTPS only, validate certificates
6. **Jailbreak/Root Detection** - Consider detecting compromised devices
