import { Tabs } from "expo-router";
import { LayoutDashboard, PlusCircle, User } from "lucide-react-native";
import { Colors } from "@/constants/Colors";

export default function TabLayout() {
  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarActiveTintColor: "#ffffff",
        tabBarInactiveTintColor: "#6b7280",
        tabBarStyle: {
          backgroundColor: Colors.slate.dark,
          borderTopWidth: 0,
          paddingBottom: 10,
          paddingTop: 8,
          height: 64,
          elevation: 0
        },
        tabBarLabelStyle: {
          fontSize: 11,
          fontWeight: "600"
        }
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: "Dashboard",
          tabBarIcon: ({ color, size }) => (
            <LayoutDashboard color={color} size={size - 2} />
          )
        }}
      />
      <Tabs.Screen
        name="create-schedule"
        options={{
          title: "New Schedule",
          tabBarIcon: ({ color, size }) => (
            <PlusCircle color={color} size={size - 2} />
          )
        }}
      />
      <Tabs.Screen
        name="profile"
        options={{
          title: "Profile",
          tabBarIcon: ({ color, size }) => (
            <User color={color} size={size - 2} />
          )
        }}
      />
    </Tabs>
  );
}
