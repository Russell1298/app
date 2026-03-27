import { View, Text, TouchableOpacity } from "react-native";
import { Calendar, Clock, Timer } from "lucide-react-native";

export interface Schedule {
  id: string;
  title: string;
  description: string;
  date: string;
  time: string;
  duration: string;
  color: string;
  status: "active" | "paused";
}

export function ScheduleCard({ schedule }: { schedule: Schedule }) {
  const isActive = schedule.status === "active";

  return (
    <TouchableOpacity
      activeOpacity={0.75}
      className="bg-white rounded-2xl overflow-hidden"
      style={{
        shadowColor: schedule.color,
        shadowOpacity: 0.1,
        shadowRadius: 10,
        shadowOffset: { width: 0, height: 2 },
        elevation: 3
      }}
    >
      {/* Top color accent bar */}
      <View className="h-1.5 w-full" style={{ backgroundColor: schedule.color }} />

      <View className="p-4">
        {/* Title row with status indicator */}
        <View className="flex-row items-center justify-between mb-1">
          <Text className="text-slate-dark text-base font-bold flex-1 mr-2">
            {schedule.title}
          </Text>
          <View className="flex-row items-center gap-1.5">
            <View
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: isActive ? "#22c55e" : "#9ca3af" }}
            />
            <Text
              className="text-xs font-medium"
              style={{ color: isActive ? "#22c55e" : "#9ca3af" }}
            >
              {isActive ? "Active" : "Paused"}
            </Text>
          </View>
        </View>

        <Text className="text-gray-500 text-sm mb-4" numberOfLines={2}>
          {schedule.description}
        </Text>

        {/* Meta row */}
        <View className="flex-row gap-4">
          <View className="flex-row items-center gap-1.5">
            <Calendar color={schedule.color} size={13} />
            <Text className="text-gray-500 text-xs font-medium">
              {schedule.date}
            </Text>
          </View>
          <View className="flex-row items-center gap-1.5">
            <Clock color={schedule.color} size={13} />
            <Text className="text-gray-500 text-xs font-medium">
              {schedule.time}
            </Text>
          </View>
          <View className="flex-row items-center gap-1.5">
            <Timer color={schedule.color} size={13} />
            <Text className="text-gray-500 text-xs font-medium">
              {schedule.duration}
            </Text>
          </View>
        </View>
      </View>
    </TouchableOpacity>
  );
}
