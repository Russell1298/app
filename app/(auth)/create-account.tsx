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
import { User, Mail, Lock, ArrowRight, ArrowLeft } from "lucide-react-native";
import { Input } from "@/components/ui/Input";
import { KeystoneLogo } from "@/components/ui/KeystoneLogo";

export default function CreateAccountScreen() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleCreate = () => {
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
            Create account
          </Text>
          <Text style={{ color: "#6b7280", fontSize: 13, marginBottom: 24 }}>
            Free forever. No credit card required.
          </Text>

          <Input
            label="Full Name"
            placeholder="Jane Smith"
            value={name}
            onChangeText={setName}
            autoCapitalize="words"
            icon={<User color="#6b7280" size={17} />}
          />
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
            placeholder="At least 8 characters"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            icon={<Lock color="#6b7280" size={17} />}
          />

          {/* CTA */}
          <TouchableOpacity
            onPress={handleCreate}
            disabled={loading}
            style={{
              backgroundColor: "#0069ff",
              borderRadius: 12,
              paddingVertical: 15,
              flexDirection: "row",
              alignItems: "center",
              justifyContent: "center",
              gap: 8,
              marginTop: 4,
              opacity: loading ? 0.7 : 1
            }}
          >
            <Text style={{ color: "#fff", fontSize: 15, fontWeight: "700" }}>
              {loading ? "Creating account…" : "Get Started"}
            </Text>
            {!loading && <ArrowRight color="#fff" size={17} />}
          </TouchableOpacity>

          {/* Back to sign in */}
          <Link href="/(auth)/sign-in" asChild>
            <TouchableOpacity
              style={{
                flexDirection: "row",
                alignItems: "center",
                justifyContent: "center",
                marginTop: 20,
                gap: 6
              }}
            >
              <ArrowLeft color="#6b7280" size={14} />
              <Text style={{ color: "#6b7280", fontSize: 13 }}>
                Back to sign in
              </Text>
            </TouchableOpacity>
          </Link>
        </View>

        <View style={{ height: 40 }} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}
