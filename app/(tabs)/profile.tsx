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
import { KeystoneLogo } from "@/components/ui/KeystoneLogo";

const MENU_SECTIONS = [
  {
    title: "Account",
    items: [
      { icon: Mail, label: "Email Preferences", accent: "#0069ff" },
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
    <SafeAreaView style={{ flex: 1, backgroundColor: "#f3f5f9" }} edges={["top"]}>
      {/* Header */}
      <View
        style={{
          backgroundColor: "#fff",
          paddingHorizontal: 20,
          paddingVertical: 16,
          borderBottomWidth: 1,
          borderBottomColor: "#f1f5f9"
        }}
      >
        <Text style={{ fontSize: 22, fontWeight: "800", color: "#031b4e", letterSpacing: -0.4 }}>
          Profile
        </Text>
      </View>

      <ScrollView style={{ flex: 1 }} showsVerticalScrollIndicator={false}>
        {/* Avatar hero card */}
        <View
          style={{
            margin: 16,
            backgroundColor: "#0069ff",
            borderRadius: 20,
            padding: 24,
            alignItems: "center",
            elevation: 3,
            shadowColor: "#0069ff",
            shadowOpacity: 0.25,
            shadowRadius: 10
          }}
        >
          <KeystoneLogo size={56} light />

          <View
            style={{
              width: 64,
              height: 64,
              borderRadius: 32,
              backgroundColor: "rgba(255,255,255,0.2)",
              alignItems: "center",
              justifyContent: "center",
              marginTop: 16,
              marginBottom: 10
            }}
          >
            <User color="white" size={30} />
          </View>
          <Text style={{ color: "#fff", fontSize: 18, fontWeight: "800" }}>
            Jane Smith
          </Text>
          <Text style={{ color: "rgba(255,255,255,0.7)", fontSize: 13, marginTop: 2 }}>
            jane@example.com
          </Text>

          {/* Stats */}
          <View
            style={{
              flexDirection: "row",
              marginTop: 20,
              backgroundColor: "rgba(255,255,255,0.15)",
              borderRadius: 12,
              width: "100%"
            }}
          >
            {[
              { label: "Schedules", value: "12" },
              { label: "Active", value: "8" },
              { label: "This Week", value: "5" }
            ].map((stat, i, arr) => (
              <View
                key={stat.label}
                style={{
                  flex: 1,
                  paddingVertical: 12,
                  alignItems: "center",
                  borderRightWidth: i < arr.length - 1 ? 1 : 0,
                  borderRightColor: "rgba(255,255,255,0.2)"
                }}
              >
                <Text style={{ color: "#fff", fontSize: 20, fontWeight: "800" }}>
                  {stat.value}
                </Text>
                <Text style={{ color: "rgba(255,255,255,0.65)", fontSize: 11, marginTop: 2 }}>
                  {stat.label}
                </Text>
              </View>
            ))}
          </View>

          <TouchableOpacity
            style={{
              marginTop: 16,
              paddingHorizontal: 24,
              paddingVertical: 9,
              borderRadius: 20,
              backgroundColor: "rgba(255,255,255,0.2)",
              borderWidth: 1,
              borderColor: "rgba(255,255,255,0.4)"
            }}
          >
            <Text style={{ color: "#fff", fontSize: 13, fontWeight: "700" }}>
              Edit Profile
            </Text>
          </TouchableOpacity>
        </View>

        {/* Menu sections */}
        {MENU_SECTIONS.map((section) => (
          <View key={section.title} style={{ marginHorizontal: 16, marginBottom: 12 }}>
            <Text
              style={{
                fontSize: 11,
                fontWeight: "700",
                color: "#9ca3af",
                textTransform: "uppercase",
                letterSpacing: 1,
                marginBottom: 8,
                paddingLeft: 4
              }}
            >
              {section.title}
            </Text>
            <View
              style={{
                backgroundColor: "#fff",
                borderRadius: 16,
                overflow: "hidden",
                elevation: 1,
                shadowColor: "#000",
                shadowOpacity: 0.04,
                shadowRadius: 6,
                borderWidth: 1,
                borderColor: "#f1f5f9"
              }}
            >
              {section.items.map((item, index) => (
                <TouchableOpacity
                  key={item.label}
                  style={{
                    flexDirection: "row",
                    alignItems: "center",
                    paddingHorizontal: 16,
                    paddingVertical: 14,
                    borderBottomWidth: index < section.items.length - 1 ? 1 : 0,
                    borderBottomColor: "#f1f5f9"
                  }}
                >
                  <View
                    style={{
                      width: 34,
                      height: 34,
                      borderRadius: 10,
                      backgroundColor: `${item.accent}18`,
                      alignItems: "center",
                      justifyContent: "center",
                      marginRight: 12
                    }}
                  >
                    <item.icon color={item.accent} size={16} />
                  </View>
                  <Text
                    style={{ flex: 1, fontSize: 14, fontWeight: "600", color: "#031b4e" }}
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
        <View style={{ marginHorizontal: 16, marginBottom: 32 }}>
          <TouchableOpacity
            onPress={() => router.replace("/(auth)/sign-in")}
            style={{
              backgroundColor: "#fff",
              borderRadius: 16,
              paddingHorizontal: 16,
              paddingVertical: 14,
              flexDirection: "row",
              alignItems: "center",
              borderWidth: 1,
              borderColor: "#fee2e2"
            }}
          >
            <View
              style={{
                width: 34,
                height: 34,
                borderRadius: 10,
                backgroundColor: "#fef2f2",
                alignItems: "center",
                justifyContent: "center",
                marginRight: 12
              }}
            >
              <LogOut color="#ef4444" size={16} />
            </View>
            <Text style={{ fontSize: 14, fontWeight: "700", color: "#ef4444" }}>
              Sign Out
            </Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}
