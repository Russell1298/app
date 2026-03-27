import { useState } from "react";
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  Platform,
  Alert
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import DateTimePicker, {
  DateTimePickerEvent
} from "@react-native-community/datetimepicker";
import { Calendar, Clock, Tag, AlignLeft } from "lucide-react-native";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { Colors } from "@/constants/Colors";

const DURATION_OPTIONS = [
  "15 min",
  "30 min",
  "45 min",
  "1 hr",
  "1.5 hr",
  "2 hr"
];

export default function CreateScheduleScreen() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [date, setDate] = useState(new Date());
  const [time, setTime] = useState(new Date());
  const [duration, setDuration] = useState("30 min");
  const [showDatePicker, setShowDatePicker] = useState(false);
  const [showTimePicker, setShowTimePicker] = useState(false);
  const [loading, setLoading] = useState(false);

  const formatDate = (d: Date) =>
    d.toLocaleDateString("en-US", {
      weekday: "short",
      month: "short",
      day: "numeric",
      year: "numeric"
    });

  const formatTime = (d: Date) =>
    d.toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      hour12: true
    });

  const onDateChange = (_: DateTimePickerEvent, selected?: Date) => {
    setShowDatePicker(Platform.OS === "ios");
    if (selected) setDate(selected);
  };

  const onTimeChange = (_: DateTimePickerEvent, selected?: Date) => {
    setShowTimePicker(Platform.OS === "ios");
    if (selected) setTime(selected);
  };

  const handleCreate = () => {
    if (!title.trim()) {
      Alert.alert("Required", "Please enter a schedule title.");
      return;
    }
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      Alert.alert("Schedule Created", `"${title}" has been added.`, [
        {
          text: "OK",
          onPress: () => {
            setTitle("");
            setDescription("");
            setDate(new Date());
            setTime(new Date());
            setDuration("30 min");
          }
        }
      ]);
    }, 800);
  };

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
          New Schedule
        </Text>
        <Text className="text-xs mt-0.5" style={{ color: Colors.text.muted }}>
          Fill in the details below
        </Text>
      </View>

      <ScrollView
        className="flex-1"
        contentContainerStyle={{ padding: 16 }}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
      >
        {/* Details card */}
        <View
          className="bg-white rounded-2xl p-5 mb-4"
          style={{ elevation: 2, shadowColor: "#000", shadowOpacity: 0.04, shadowRadius: 8 }}
        >
          <Text
            className="text-sm font-semibold mb-4"
            style={{ color: Colors.slate.dark }}
          >
            Details
          </Text>
          <Input
            label="Title"
            placeholder="e.g. Team Standup"
            value={title}
            onChangeText={setTitle}
            icon={<Tag color="#6b7280" size={17} />}
          />
          <Input
            label="Description"
            placeholder="Optional notes or agenda..."
            value={description}
            onChangeText={setDescription}
            multiline
            numberOfLines={3}
            textAlignVertical="top"
            icon={<AlignLeft color="#6b7280" size={17} />}
          />
        </View>

        {/* Date & Time card */}
        <View
          className="bg-white rounded-2xl p-5 mb-4"
          style={{ elevation: 2, shadowColor: "#000", shadowOpacity: 0.04, shadowRadius: 8 }}
        >
          <Text
            className="text-sm font-semibold mb-4"
            style={{ color: Colors.slate.dark }}
          >
            Date & Time
          </Text>

          {/* Date trigger */}
          <TouchableOpacity
            onPress={() => setShowDatePicker(true)}
            className="flex-row items-center rounded-xl px-4 mb-3"
            style={{
              paddingVertical: 14,
              borderWidth: 1,
              borderColor: "#e5e7eb",
              backgroundColor: "#f9fafb"
            }}
          >
            <Calendar color={Colors.primary} size={17} />
            <Text
              className="ml-3 text-sm font-medium"
              style={{ color: Colors.slate.dark }}
            >
              {formatDate(date)}
            </Text>
          </TouchableOpacity>

          {/* Time trigger */}
          <TouchableOpacity
            onPress={() => setShowTimePicker(true)}
            className="flex-row items-center rounded-xl px-4"
            style={{
              paddingVertical: 14,
              borderWidth: 1,
              borderColor: "#e5e7eb",
              backgroundColor: "#f9fafb"
            }}
          >
            <Clock color={Colors.primary} size={17} />
            <Text
              className="ml-3 text-sm font-medium"
              style={{ color: Colors.slate.dark }}
            >
              {formatTime(time)}
            </Text>
          </TouchableOpacity>

          {/* Pickers (shown inline on iOS, modal on Android) */}
          {showDatePicker && (
            <DateTimePicker
              value={date}
              mode="date"
              display={Platform.OS === "ios" ? "spinner" : "default"}
              onChange={onDateChange}
              minimumDate={new Date()}
            />
          )}
          {showTimePicker && (
            <DateTimePicker
              value={time}
              mode="time"
              display={Platform.OS === "ios" ? "spinner" : "default"}
              onChange={onTimeChange}
            />
          )}
        </View>

        {/* Duration card */}
        <View
          className="bg-white rounded-2xl p-5 mb-6"
          style={{ elevation: 2, shadowColor: "#000", shadowOpacity: 0.04, shadowRadius: 8 }}
        >
          <Text
            className="text-sm font-semibold mb-4"
            style={{ color: Colors.slate.dark }}
          >
            Duration
          </Text>
          <View className="flex-row flex-wrap gap-2">
            {DURATION_OPTIONS.map((opt) => (
              <TouchableOpacity
                key={opt}
                onPress={() => setDuration(opt)}
                className="px-4 py-2 rounded-full"
                style={{
                  borderWidth: 1.5,
                  borderColor: duration === opt ? Colors.primary : "#e5e7eb",
                  backgroundColor: duration === opt ? Colors.primary : "#fff"
                }}
              >
                <Text
                  className="text-sm font-semibold"
                  style={{ color: duration === opt ? "#fff" : "#6b7280" }}
                >
                  {opt}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>

        <Button title="Create Schedule" onPress={handleCreate} loading={loading} />

        <View className="h-6" />
      </ScrollView>
    </SafeAreaView>
  );
}
