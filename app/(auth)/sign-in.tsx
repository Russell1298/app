import { useState } from "react";
import {
  View,
  Text,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  TouchableOpacity
} from "react-native";
import { Link, router } from "expo-router";
import { Mail, Lock, ArrowRight } from "lucide-react-native";
import { Input } from "@/components/ui/Input";
import { KeystoneLogo } from "@/components/ui/KeystoneLogo";

export default function SignInScreen() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSignIn = () => {
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      router.replace("/(tabs)");
    }, 900);
  };

  return (
    <KeyboardAvoidingView
      style={{ flex: 1, backgroundColor: "#ffffff" }}
      behavior={Platform.OS === "ios" ? "padding" : "height"}
    >
      <ScrollView
        contentContainerStyle={{ flexGrow: 1 }}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
      >
        {/* Top blue hero band */}
        <View
          style={{
            backgroundColor: "#0069ff",
            paddingTop: 72,
            paddingBottom: 48,
            paddingHorizontal: 28,
            alignItems: "center"
          }}
        >
          <KeystoneLogo size={80} light />
          <Text
            style={{
              color: "#ffffff",
              fontSize: 26,
              fontWeight: "800",
              marginTop: 16,
              letterSpacing: -0.5
            }}
          >
            Keystone
          </Text>
          <Text style={{ color: "#bfdbfe", fontSize: 14, marginTop: 4 }}>
            Smart scheduling, simplified.
          </Text>
        </View>

        {/* Form area */}
        <View style={{ flex: 1, paddingHorizontal: 24, paddingTop: 32 }}>
          <Text
            style={{
              fontSize: 20,
              fontWeight: "700",
              color: "#031b4e",
              marginBottom: 4
            }}
          >
            Sign in
          </Text>
          <Text style={{ color: "#6b7280", fontSize: 13, marginBottom: 24 }}>
            Welcome back — enter your credentials below.
          </Text>

          <Input
            label="Email address"
            placeholder="you@example.com"
            value={email}
            onChangeText={setEmail}
            keyboardType="email-address"
            autoCapitalize="none"
            autoCorrect={false}
            icon={<Mail color="#6b7280" size={17} />}
          />
          <Input
            label="Password"
            placeholder="••••••••"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            icon={<Lock color="#6b7280" size={17} />}
          />

          <TouchableOpacity style={{ alignSelf: "flex-end", marginBottom: 20 }}>
            <Text style={{ color: "#0069ff", fontSize: 13, fontWeight: "600" }}>
              Forgot password?
            </Text>
          </TouchableOpacity>

          {/* CTA button */}
          <TouchableOpacity
            onPress={handleSignIn}
            disabled={loading}
            style={{
              backgroundColor: "#0069ff",
              borderRadius: 12,
              paddingVertical: 15,
              flexDirection: "row",
              alignItems: "center",
              justifyContent: "center",
              gap: 8,
              opacity: loading ? 0.7 : 1
            }}
          >
            <Text
              style={{ color: "#fff", fontSize: 15, fontWeight: "700" }}
            >
              {loading ? "Signing in…" : "Sign In"}
            </Text>
            {!loading && <ArrowRight color="#fff" size={17} />}
          </TouchableOpacity>

          {/* Divider */}
          <View
            style={{
              flexDirection: "row",
              alignItems: "center",
              marginVertical: 24
            }}
          >
            <View style={{ flex: 1, height: 1, backgroundColor: "#e5e7eb" }} />
            <Text style={{ marginHorizontal: 12, color: "#9ca3af", fontSize: 12 }}>
              OR
            </Text>
            <View style={{ flex: 1, height: 1, backgroundColor: "#e5e7eb" }} />
          </View>

          <Link href="/(auth)/create-account" asChild>
            <TouchableOpacity
              style={{
                borderWidth: 1.5,
                borderColor: "#0069ff",
                borderRadius: 12,
                paddingVertical: 14,
                alignItems: "center"
              }}
            >
              <Text
                style={{ color: "#0069ff", fontSize: 15, fontWeight: "700" }}
              >
                Create an account
              </Text>
            </TouchableOpacity>
          </Link>
        </View>

        <View style={{ height: 40 }} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}
