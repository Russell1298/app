import { useState } from "react";
import {
  View,
  Text,
  ScrollView,
  RefreshControl,
  TouchableOpacity
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { Bell, Search } from "lucide-react-native";
import { ScheduleCard, Schedule } from "@/components/schedule/ScheduleCard";
import { Colors } from "@/constants/Colors";

const MOCK_SCHEDULES: Schedule[] = [
  {
    id: "1",
    title: "Team Standup",
    description: "Daily sync with the engineering team — blockers, progress, priorities.",
    date: "Mon, Mar 30",
    time: "9:00 AM",
    duration: "30 min",
    color: Colors.primary,
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
    <SafeAreaView
      className="flex-1"
      style={{ backgroundColor: Colors.background }}
      edges={["top"]}
    >
      {/* Header */}
      <View
        className="flex-row items-center justify-between px-5 py-4 bg-white"
        style={{ borderBottomWidth: 1, borderBottomColor: "#f1f5f9" }}
      >
        <View>
          <Text
            className="text-xl font-bold"
            style={{ color: Colors.slate.dark }}
          >
            Dashboard
          </Text>
          <Text className="text-xs mt-0.5" style={{ color: Colors.text.muted }}>
            {activeCount} active · {MOCK_SCHEDULES.length} total
          </Text>
        </View>
        <View className="flex-row gap-2">
          <TouchableOpacity
            className="w-9 h-9 rounded-full items-center justify-center"
            style={{ backgroundColor: Colors.background }}
          >
            <Search color={Colors.slate.dark} size={17} />
          </TouchableOpacity>
          <TouchableOpacity
            className="w-9 h-9 rounded-full items-center justify-center"
            style={{ backgroundColor: Colors.background }}
          >
            <Bell color={Colors.slate.dark} size={17} />
          </TouchableOpacity>
        </View>
      </View>

      <ScrollView
        className="flex-1"
        contentContainerStyle={{ padding: 16, gap: 12 }}
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
        <Text
          className="text-xs font-semibold uppercase tracking-widest px-1 mb-1"
          style={{ color: Colors.text.muted }}
        >
          Upcoming Schedules
        </Text>

        {MOCK_SCHEDULES.map((schedule) => (
          <ScheduleCard key={schedule.id} schedule={schedule} />
        ))}

        {/* Bottom spacer */}
        <View className="h-4" />
      </ScrollView>
    </SafeAreaView>
  );
}
