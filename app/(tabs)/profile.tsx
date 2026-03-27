import { View, Text, TouchableOpacity, ScrollView } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import {
  User,
  Mail,
  Bell,
  Shield,
  HelpCircle,
  LogOut,
  ChevronRight,
  Calendar
} from "lucide-react-native";
import { router } from "expo-router";
import { Colors } from "@/constants/Colors";

const MENU_SECTIONS = [
  {
    title: "Account",
    items: [
      { icon: Mail, label: "Email Preferences", accent: Colors.primary },
      { icon: Bell, label: "Notifications", accent: "#7c3aed" },
      { icon: Shield, label: "Privacy & Security", accent: "#059669" },
      { icon: Calendar, label: "Calendar Sync", accent: "#d97706" }
    ]
  },
  {
    title: "Support",
    items: [
      { icon: HelpCircle, label: "Help Center", accent: "#6b7280" }
    ]
  }
] as const;

export default function ProfileScreen() {
  return (
    <SafeAreaView
      className="flex-1"
      style={{ backgroundColor: Colors.background }}
      edges={["top"]}
    >
      {/* Header */}
      <View
        className="px-5 py-4 bg-white"
        style={{ borderBottomWidth: 1, borderBottomColor: "#f1f5f9" }}
      >
        <Text
          className="text-xl font-bold"
          style={{ color: Colors.slate.dark }}
        >
          Profile
        </Text>
      </View>

      <ScrollView className="flex-1" showsVerticalScrollIndicator={false}>
        {/* Avatar card */}
        <View
          className="mx-4 mt-4 mb-4 bg-white rounded-2xl p-6 items-center"
          style={{ elevation: 2, shadowColor: "#000", shadowOpacity: 0.04, shadowRadius: 8 }}
        >
          <View
            className="w-20 h-20 rounded-full items-center justify-center mb-3"
            style={{ backgroundColor: Colors.primary }}
          >
            <User color="white" size={36} />
          </View>
          <Text
            className="text-lg font-bold"
            style={{ color: Colors.slate.dark }}
          >
            Jane Smith
          </Text>
          <Text className="text-sm mt-0.5" style={{ color: Colors.text.muted }}>
            jane@example.com
          </Text>

          {/* Stats row */}
          <View
            className="flex-row mt-5 w-full rounded-xl overflow-hidden"
            style={{ backgroundColor: Colors.background }}
          >
            {[
              { label: "Schedules", value: "12" },
              { label: "Active", value: "8" },
              { label: "This Week", value: "5" }
            ].map((stat, i, arr) => (
              <View
                key={stat.label}
                className="flex-1 py-3 items-center"
                style={{
                  borderRightWidth: i < arr.length - 1 ? 1 : 0,
                  borderRightColor: Colors.border
                }}
              >
                <Text
                  className="text-lg font-bold"
                  style={{ color: Colors.primary }}
                >
                  {stat.value}
                </Text>
                <Text className="text-xs mt-0.5" style={{ color: Colors.text.muted }}>
                  {stat.label}
                </Text>
              </View>
            ))}
          </View>

          <TouchableOpacity
            className="mt-4 px-6 py-2 rounded-full"
            style={{ borderWidth: 1.5, borderColor: Colors.primary }}
          >
            <Text
              className="text-sm font-semibold"
              style={{ color: Colors.primary }}
            >
              Edit Profile
            </Text>
          </TouchableOpacity>
        </View>

        {/* Menu sections */}
        {MENU_SECTIONS.map((section) => (
          <View key={section.title} className="mx-4 mb-4">
            <Text
              className="text-xs font-semibold uppercase tracking-widest mb-2 px-1"
              style={{ color: Colors.text.muted }}
            >
              {section.title}
            </Text>
            <View
              className="bg-white rounded-2xl overflow-hidden"
              style={{ elevation: 2, shadowColor: "#000", shadowOpacity: 0.04, shadowRadius: 8 }}
            >
              {section.items.map((item, index) => (
                <TouchableOpacity
                  key={item.label}
                  className="flex-row items-center px-4 py-4"
                  style={{
                    borderBottomWidth: index < section.items.length - 1 ? 1 : 0,
                    borderBottomColor: "#f1f5f9"
                  }}
                >
                  <View
                    className="w-8 h-8 rounded-lg items-center justify-center mr-3"
                    style={{ backgroundColor: `${item.accent}18` }}
                  >
                    <item.icon color={item.accent} size={16} />
                  </View>
                  <Text
                    className="flex-1 text-sm font-medium"
                    style={{ color: Colors.slate.dark }}
                  >
                    {item.label}
                  </Text>
                  <ChevronRight color="#d1d5db" size={16} />
                </TouchableOpacity>
              ))}
            </View>
          </View>
        ))}

        {/* Sign out */}
        <View className="mx-4 mb-10">
          <TouchableOpacity
            className="bg-white rounded-2xl px-4 py-4 flex-row items-center"
            style={{ elevation: 2, shadowColor: "#000", shadowOpacity: 0.04, shadowRadius: 8 }}
            onPress={() => router.replace("/(auth)/sign-in")}
          >
            <View className="w-8 h-8 rounded-lg items-center justify-center mr-3 bg-red-50">
              <LogOut color="#ef4444" size={16} />
            </View>
            <Text className="text-sm font-semibold text-red-500">Sign Out</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}
