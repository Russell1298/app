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
import { User, Mail, Lock, UserPlus } from "lucide-react-native";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";

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
      className="flex-1"
      style={{ backgroundColor: "#031b4e" }}
      behavior={Platform.OS === "ios" ? "padding" : "height"}
    >
      <ScrollView
        contentContainerStyle={{ flexGrow: 1 }}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
      >
        <View className="flex-1 justify-center px-6 py-16">
          {/* Branding */}
          <View className="mb-10">
            <View
              className="w-14 h-14 rounded-2xl items-center justify-center mb-5"
              style={{ backgroundColor: "#0069ff" }}
            >
              <UserPlus color="white" size={28} />
            </View>
            <Text className="text-white text-3xl font-bold tracking-tight">
              Create account
            </Text>
            <Text className="mt-1.5 text-base" style={{ color: "#93c5fd" }}>
              Get started for free today
            </Text>
          </View>

          {/* Card */}
          <View className="bg-white rounded-2xl p-6">
            <Input
              label="Full Name"
              placeholder="Jane Smith"
              value={name}
              onChangeText={setName}
              autoCapitalize="words"
              icon={<User color="#6b7280" size={18} />}
            />
            <Input
              label="Email address"
              placeholder="you@example.com"
              value={email}
              onChangeText={setEmail}
              keyboardType="email-address"
              autoCapitalize="none"
              autoCorrect={false}
              icon={<Mail color="#6b7280" size={18} />}
            />
            <Input
              label="Password"
              placeholder="At least 8 characters"
              value={password}
              onChangeText={setPassword}
              secureTextEntry
              icon={<Lock color="#6b7280" size={18} />}
            />

            <Button
              title="Create Account"
              onPress={handleCreate}
              loading={loading}
            />
          </View>

          {/* Footer */}
          <View className="flex-row justify-center mt-8">
            <Text style={{ color: "#bfdbfe" }} className="text-sm">
              Already have an account?{" "}
            </Text>
            <Link href="/(auth)/sign-in" asChild>
              <TouchableOpacity>
                <Text className="text-white text-sm font-semibold">
                  Sign in
                </Text>
              </TouchableOpacity>
            </Link>
          </View>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}
