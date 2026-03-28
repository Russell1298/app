import { useState } from "react";
import {
  View,
  Text,
  ScrollView,
  RefreshControl,
  TouchableOpacity
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import {
  Bell,
  Plus,
  CalendarDays,
  Clock4,
  Users,
  Repeat2,
  ChevronRight
} from "lucide-react-native";
import { router } from "expo-router";
import { ScheduleCard, Schedule } from "@/components/schedule/ScheduleCard";
import { Colors } from "@/constants/Colors";

const QUICK_ACTIONS = [
  {
    label: "One-time",
    icon: CalendarDays,
    color: "#0069ff",
    bg: "#eff6ff"
  },
  {
    label: "Recurring",
    icon: Repeat2,
    color: "#7c3aed",
    bg: "#f5f3ff"
  },
  {
    label: "With Team",
    icon: Users,
    color: "#059669",
    bg: "#ecfdf5"
  },
  {
    label: "Time Block",
    icon: Clock4,
    color: "#d97706",
    bg: "#fffbeb"
  }
];

const MOCK_SCHEDULES: Schedule[] = [
  {
    id: "1",
    title: "Team Standup",
    description: "Daily sync with the engineering team — blockers, progress, priorities.",
    date: "Mon, Mar 30",
    time: "9:00 AM",
    duration: "30 min",
    color: "#0069ff",
    status: "active"
  },
  {
    id: "2",
    title: "Product Review",
    description: "Quarterly product roadmap review with stakeholders.",
    date: "Tue, Apr 1",
    time: "2:00 PM",
    duration: "1 hr",
    color: "#7c3aed",
    status: "active"
  },
  {
    id: "3",
    title: "Client Demo",
    description: "Live demo for Acme Corp — focus on new reporting features.",
    date: "Wed, Apr 2",
    time: "11:00 AM",
    duration: "45 min",
    color: "#059669",
    status: "paused"
  },
  {
    id: "4",
    title: "Sprint Retrospective",
    description: "Sprint 24 retro — what went well, what to improve.",
    date: "Fri, Apr 4",
    time: "4:00 PM",
    duration: "1 hr",
    color: "#d97706",
    status: "active"
  },
  {
    id: "5",
    title: "1:1 with Manager",
    description: "Bi-weekly check-in on goals and career development.",
    date: "Mon, Apr 7",
    time: "10:30 AM",
    duration: "30 min",
    color: "#e11d48",
    status: "paused"
  }
];

export default function DashboardScreen() {
  const [refreshing, setRefreshing] = useState(false);

  const onRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 1000);
  };

  const activeCount = MOCK_SCHEDULES.filter((s) => s.status === "active").length;

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: "#f3f5f9" }} edges={["top"]}>
      {/* Header */}
      <View
        style={{
          backgroundColor: "#ffffff",
          paddingHorizontal: 20,
          paddingTop: 16,
          paddingBottom: 16,
          flexDirection: "row",
          alignItems: "center",
          justifyContent: "space-between",
          borderBottomWidth: 1,
          borderBottomColor: "#f1f5f9"
        }}
      >
        <View>
          <Text style={{ fontSize: 22, fontWeight: "800", color: "#031b4e", letterSpacing: -0.4 }}>
            Keystone
          </Text>
          <Text style={{ fontSize: 12, color: "#6b7280", marginTop: 1 }}>
            {activeCount} active · {MOCK_SCHEDULES.length} schedules
          </Text>
        </View>
        <View style={{ flexDirection: "row", gap: 8 }}>
          <TouchableOpacity
            style={{
              width: 36,
              height: 36,
              borderRadius: 18,
              backgroundColor: "#f3f5f9",
              alignItems: "center",
              justifyContent: "center"
            }}
          >
            <Bell color="#031b4e" size={17} />
          </TouchableOpacity>
          <TouchableOpacity
            onPress={() => router.push("/(tabs)/create-schedule")}
            style={{
              height: 36,
              paddingHorizontal: 14,
              borderRadius: 18,
              backgroundColor: "#0069ff",
              alignItems: "center",
              justifyContent: "center",
              flexDirection: "row",
              gap: 5
            }}
          >
            <Plus color="#fff" size={15} />
            <Text style={{ color: "#fff", fontSize: 13, fontWeight: "700" }}>
              New
            </Text>
          </TouchableOpacity>
        </View>
      </View>

      <ScrollView
        style={{ flex: 1 }}
        contentContainerStyle={{ paddingBottom: 32 }}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            tintColor={Colors.primary}
            colors={[Colors.primary]}
          />
        }
        showsVerticalScrollIndicator={false}
      >
        {/* Quick Actions */}
        <View style={{ paddingHorizontal: 16, paddingTop: 20, paddingBottom: 4 }}>
          <Text
            style={{
              fontSize: 11,
              fontWeight: "700",
              color: "#9ca3af",
              textTransform: "uppercase",
              letterSpacing: 1,
              marginBottom: 12
            }}
          >
            Quick Schedule
          </Text>
          <View style={{ flexDirection: "row", gap: 10 }}>
            {QUICK_ACTIONS.map((action) => (
              <TouchableOpacity
                key={action.label}
                onPress={() => router.push("/(tabs)/create-schedule")}
                activeOpacity={0.75}
                style={{
                  flex: 1,
                  backgroundColor: "#ffffff",
                  borderRadius: 14,
                  paddingVertical: 14,
                  alignItems: "center",
                  gap: 8,
                  borderWidth: 1,
                  borderColor: "#f1f5f9",
                  elevation: 1,
                  shadowColor: "#000",
                  shadowOpacity: 0.04,
                  shadowRadius: 4
                }}
              >
                <View
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 10,
                    backgroundColor: action.bg,
                    alignItems: "center",
                    justifyContent: "center"
                  }}
                >
                  <action.icon color={action.color} size={18} />
                </View>
                <Text
                  style={{
                    fontSize: 11,
                    fontWeight: "600",
                    color: "#374151",
                    textAlign: "center"
                  }}
                >
                  {action.label}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>

        {/* Stats row */}
        <View
          style={{
            marginHorizontal: 16,
            marginTop: 16,
            backgroundColor: "#0069ff",
            borderRadius: 16,
            padding: 16,
            flexDirection: "row",
            elevation: 2,
            shadowColor: "#0069ff",
            shadowOpacity: 0.25,
            shadowRadius: 8
          }}
        >
          {[
            { label: "Total", value: `${MOCK_SCHEDULES.length}` },
            { label: "Active", value: `${activeCount}` },
            { label: "This Week", value: "3" },
            { label: "Paused", value: `${MOCK_SCHEDULES.length - activeCount}` }
          ].map((stat, i, arr) => (
            <View
              key={stat.label}
              style={{
                flex: 1,
                alignItems: "center",
                borderRightWidth: i < arr.length - 1 ? 1 : 0,
                borderRightColor: "rgba(255,255,255,0.2)"
              }}
            >
              <Text style={{ color: "#ffffff", fontSize: 22, fontWeight: "800" }}>
                {stat.value}
              </Text>
              <Text style={{ color: "rgba(255,255,255,0.7)", fontSize: 11, marginTop: 2 }}>
                {stat.label}
              </Text>
            </View>
          ))}
        </View>

        {/* Schedules list */}
        <View style={{ paddingHorizontal: 16, marginTop: 20 }}>
          <View
            style={{
              flexDirection: "row",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 12
            }}
          >
            <Text
              style={{
                fontSize: 11,
                fontWeight: "700",
                color: "#9ca3af",
                textTransform: "uppercase",
                letterSpacing: 1
              }}
            >
              Upcoming
            </Text>
            <TouchableOpacity style={{ flexDirection: "row", alignItems: "center", gap: 2 }}>
              <Text style={{ fontSize: 12, color: "#0069ff", fontWeight: "600" }}>
                See all
              </Text>
              <ChevronRight color="#0069ff" size={13} />
            </TouchableOpacity>
          </View>

          <View style={{ gap: 10 }}>
            {MOCK_SCHEDULES.map((schedule) => (
              <ScheduleCard key={schedule.id} schedule={schedule} />
            ))}
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}
